use std::io;
use std::process::ExitCode;

use liskov_runtime_cargo::network_traversal::{
    run_external_traversal, run_offline_traversal_scenario,
};
use liskov_runtime_cargo::processor_facts::run_fact_probe_self_test;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let result = match (args.next(), args.next()) {
        (None, None) => {
            let input = include_bytes!("../../tools/qemu-proot/traversal-scenario-v1.json");
            if !run_fact_probe_self_test() {
                Err("processor fact fixture failed")
            } else {
                run_offline_traversal_scenario(input.as_slice())
                    .map(|_| println!("liskov-fact-probe: ok"))
            }
        }
        (Some(flag), None) if flag == "--traversal-scenario" => {
            run_offline_traversal_scenario(io::stdin().lock())
                .map(|transcript| println!("{transcript}"))
        }
        (Some(flag), None) if flag == "--traversal-external" => {
            return match run_external_traversal() {
                Ok(()) => ExitCode::SUCCESS,
                Err(code) => {
                    eprintln!("{code}");
                    ExitCode::FAILURE
                }
            };
        }
        _ => Err("usage: liskov-fact-probe [--traversal-scenario | --traversal-external]"),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("liskov-fact-probe: {error}");
            ExitCode::FAILURE
        }
    }
}
