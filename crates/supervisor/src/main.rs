#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use hearthrun_domain::protocol::Request;
    use hearthrun_supervisor::{
        profiles,
        scheduler::{Config, Response, Scheduler},
        server::{Connection, ErrorCode, Reply, Server, MAX_CONNECTIONS},
        staging::Stages,
        store::Store,
    };
    use std::io;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
    #[cfg(not(feature = "cancellation-timing-verification"))]
    type Work = (Request, mpsc::SyncSender<Response>);
    #[cfg(feature = "cancellation-timing-verification")]
    type Work = (
        Request,
        mpsc::SyncSender<Response>,
        Option<hearthrun_supervisor::cancel_timing::Receipt>,
    );
    static STOP: AtomicBool = AtomicBool::new(false);

    extern "C" fn signal_stop(_: libc::c_int) {
        STOP.store(true, Ordering::Relaxed);
    }

    fn install_signals() -> io::Result<()> {
        // SAFETY: sigaction is initialized before use. The handler only
        // writes a lock-free atomic and is shared by SIGINT and SIGTERM.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = signal_stop as *const () as usize;
            if libc::sigemptyset(&mut action.sa_mask) < 0
                || libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()) < 0
                || libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    fn client(
        connection: Connection,
        stages: &Stages,
        work: &mpsc::SyncSender<Work>,
    ) -> io::Result<()> {
        let incoming = match connection.receive() {
            Ok(incoming) => incoming,
            Err(error) => return error.respond(),
        };
        if matches!(incoming.request(), Request::Stage(_)) {
            if STOP.load(Ordering::Relaxed) {
                return incoming.reject(hearthrun_supervisor::server::ErrorReply::new(
                    ErrorCode::IoUncertain,
                    "supervisor is shutting down",
                ));
            }
            return stages.receive(incoming);
        }
        let valid = match incoming.finish() {
            Ok(valid) => valid,
            Err(error) => return error.respond(),
        };
        #[cfg(feature = "cancellation-timing-verification")]
        let mut valid = valid;
        #[cfg(feature = "cancellation-timing-verification")]
        let receipt = valid.take_receipt();
        let (request, responder) = valid.into_parts();
        let (reply, waiting) = mpsc::sync_channel(1);
        #[cfg(not(feature = "cancellation-timing-verification"))]
        let sent = work.try_send((request, reply));
        #[cfg(feature = "cancellation-timing-verification")]
        let sent = work.try_send((request, reply, receipt));
        if sent.is_err() {
            return responder.respond(Reply::error(
                ErrorCode::QueueFull,
                "local request lanes are busy",
            ));
        }
        match waiting.recv_timeout(Duration::from_secs(8)) {
            Ok(response) => responder.respond(response.resolve()),
            Err(_) => responder.respond(Reply::error(
                ErrorCode::IoUncertain,
                "operation has no confirmed reply; use the same request ID",
            )),
        }
    }

    fn collect(workers: &mut Vec<JoinHandle<io::Result<()>>>) -> io::Result<()> {
        let mut index = 0;
        while index < workers.len() {
            if workers[index].is_finished() {
                let finished = workers
                    .swap_remove(index)
                    .join()
                    .map_err(|_| io::Error::other("IPC worker panicked"))?;
                if let Err(error) = finished {
                    eprintln!("IPC request ended: {error}");
                }
            } else {
                index += 1;
            }
        }
        Ok(())
    }

    fn serve(cfg: Config) -> Result<()> {
        #[cfg(feature = "cancellation-timing-verification")]
        let trace = hearthrun_supervisor::cancel_timing::Trace::start()?;
        install_signals()?;
        let state = cfg.state.clone();
        let mut scheduler = Scheduler::open(cfg)?;
        let mut socket = Server::bind(&state, rustix::process::geteuid().as_raw())?;
        let (work, requests) = mpsc::sync_channel::<Work>(MAX_CONNECTIONS);
        let mut workers = Vec::new();
        let mut closing = None;
        let mut failure = None;
        loop {
            if closing.is_none() && (STOP.load(Ordering::Relaxed) || failure.is_some()) {
                STOP.store(true, Ordering::Relaxed);
                closing = Some(Instant::now() + Duration::from_secs(16));
                if let Err(error) = scheduler.shutdown() {
                    eprintln!("shutdown could not commit: {error}");
                    failure.get_or_insert(error);
                }
            }
            if failure.is_none() {
                if let Err(error) = scheduler.tick() {
                    failure = Some(error);
                }
            } else if let Err(error) = scheduler.cleanup_failed() {
                eprintln!("cleanup after service failure remains pending: {error}");
            }
            if closing.is_none() && failure.is_none() && workers.len() < MAX_CONNECTIONS {
                match socket.poll_accept() {
                    Ok(Some(connection)) => {
                        let work = work.clone();
                        let stage = Arc::clone(&scheduler.stages);
                        let started = scheduler.retain_storage().and_then(|lease| {
                            thread::Builder::new()
                                .name("hearthrun-ipc".into())
                                .stack_size(512 * 1024)
                                .spawn(move || {
                                    let _lease = lease;
                                    client(connection, &stage, &work)
                                })
                        });
                        match started {
                            Ok(worker) => workers.push(worker),
                            Err(error) => failure = Some(error.into()),
                        }
                    }
                    Ok(None) => {}
                    Err(error) => failure = Some(error.into()),
                }
            }
            for _ in 0..MAX_CONNECTIONS {
                let Ok(work) = requests.try_recv() else {
                    break;
                };
                #[cfg(not(feature = "cancellation-timing-verification"))]
                let (request, reply) = work;
                #[cfg(feature = "cancellation-timing-verification")]
                let (request, reply, receipt) = work;
                let response = if failure.is_some() {
                    Response::Immediate(Reply::error(
                        ErrorCode::IoUncertain,
                        "service requires recovery",
                    ))
                } else {
                    #[cfg(not(feature = "cancellation-timing-verification"))]
                    let result = scheduler.request(request);
                    #[cfg(feature = "cancellation-timing-verification")]
                    let result = scheduler.request_observed(request, receipt);
                    result
                };
                // A disconnected client does not revoke the durable request.
                if reply.send(response).is_err() {
                    eprintln!("client disconnected before response");
                }
            }
            if let Err(error) = collect(&mut workers) {
                failure.get_or_insert(error.into());
            }
            if let Some(deadline) = closing {
                if scheduler.is_idle() && workers.is_empty() {
                    break;
                }
                if Instant::now() >= deadline {
                    failure.get_or_insert_with(|| {
                        io::Error::other("CLEANUP_PENDING at shutdown").into()
                    });
                    break;
                }
            }
            thread::sleep(Duration::from_millis(3));
        }
        socket.close()?;
        #[cfg(feature = "cancellation-timing-verification")]
        trace.finish(failure.is_none())?;
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(())
    }

    fn absolute(value: std::ffi::OsString) -> io::Result<PathBuf> {
        let path = PathBuf::from(value);
        if path.is_absolute() {
            Ok(path)
        } else {
            Err(io::Error::other("absolute operator path required"))
        }
    }

    pub(super) fn run() -> Result<()> {
        let _ = rustix::process::umask(rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO);
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        match args.as_slice() {
            [operation,state,id,source] if operation == "install-profile" => {
                let state = absolute(state.to_owned())?;
                let store = Store::open(&state)?;
                let id = id.to_str().ok_or_else(||io::Error::other("profile identifier must be text"))?;
                let profile = profiles::install(store.root(),id,&absolute(source.to_owned())?)?;
                println!("{}",serde_json::json!({"profile_id":id,"profile_digest":profile.digest,"executable_digest":profile.image_digest}));
                Ok(())
            }
            [operation,state,root,launcher,doctor] if operation == "serve" => {
                let root = if root == "-" { None } else { Some(absolute(root.to_owned())?) };
                serve(Config {state:absolute(state.to_owned())?,root,
                    launcher:absolute(launcher.to_owned())?,doctor:absolute(doctor.to_owned())?})
            }
            _ => {
                Err(io::Error::other("usage: hearthrun-supervisor serve STATE CGROUP_ROOT|- LAUNCHER DOCTOR | install-profile STATE ID EXECUTABLE").into())
            }
        }
    }
}

fn main() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if let Err(error) = linux::run() {
        let errno = error
            .source()
            .and_then(|cause| cause.downcast_ref::<std::io::Error>())
            .and_then(std::io::Error::raw_os_error);
        if let Some(errno) = errno {
            eprintln!("hearthrun-supervisor: {error} (os error {errno})");
        } else {
            eprintln!("hearthrun-supervisor: {error}");
        }
        std::process::exit(1);
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        eprintln!("HearthRun supervisor requires Linux x86-64");
        std::process::exit(78);
    }
}
