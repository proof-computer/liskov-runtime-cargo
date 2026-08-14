use std::process::ExitCode;

fn main() -> ExitCode {
    if liskov_runtime_cargo::processor_facts::run_fact_probe_self_test() {
        println!("liskov-fact-probe: ok");
        ExitCode::SUCCESS
    } else {
        eprintln!("liskov-fact-probe: failed");
        ExitCode::FAILURE
    }
}
