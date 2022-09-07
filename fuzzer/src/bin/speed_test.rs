use angora::executor::Forksrv;

use anyhow::{anyhow, Context};
use std::{
    collections::HashMap,
    env,
    ffi::OsString,
    os::unix::io::RawFd,
    time::{Duration, SystemTime},
};

static FUZZER_ID_VAR: &str = "ANGORA_FUZZER_ID";
const TIME_LIMIT: Duration = Duration::from_secs(5);
const MEM_LIMIT: u64 = 2000;

fn main() -> Result<(), anyhow::Error> {
    let args: Vec<_> = env::args_os().collect();
    if args.len() < 2 {
        return Err(anyhow!("Wrong command!"));
    }

    let prom_bin = args[1].clone();
    let prom_args = vec![args[2].clone()];

    // TODO bind cpu

    let mut envs = HashMap::new();
    let thread_id = 0;
    envs.insert(OsString::from(FUZZER_ID_VAR), thread_id.to_string().into());
    // envs.insert(BRANCHES_SHM_ENV_VAR.to_string(), branches.get_id().to_string());
    // envs.insert(COND_STMT_ENV_VAR.to_string(), cond_stmt.get_id().to_string());
    let mut fs = Forksrv::new(
        "/tmp/angora_speeed_test",
        &(prom_bin.into(), prom_args),
        &envs,
        0 as RawFd,
        false,
        false,
        TIME_LIMIT,
        MEM_LIMIT,
    )
    .context("Could not initialize fork server")?;

    let init_t = SystemTime::now();
    let n = 10000;
    for _ in 0..n {
        fs.run()
            .expect("Spawning new child from fork server failed");
    }

    let running_time = init_t.elapsed().unwrap().as_secs();
    println!("t: {}, n {} ", running_time, n);

    Ok(())
}
