use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use rayon::prelude::*;
use ruff_python_ast::Mod;
use ruff_python_parser;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;
use rand::Rng;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <path>", args[0]);
        return;
    }
    let path = &args[1];

    let asts = Arc::new(Mutex::new(HashMap::new()));

    let start = Instant::now();

    let paths = collect_paths_parallel(path);
    let line_count = parse_files_parallel(&paths, &asts);

    let duration = start.elapsed();
    let asts_len = asts.lock().unwrap().len();
    let original_load_time = duration.as_secs_f32();

    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher = RecommendedWatcher::new(tx, Config::default()).unwrap();
    watcher
        .watch(path.as_ref(), RecursiveMode::Recursive)
        .unwrap();

    // Every few seconds, print a random AST:
    let asts_clone = Arc::clone(&asts);
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(3));
        let asts_guard = asts_clone.lock().unwrap();

        if !asts_guard.is_empty() {
            let mut rng = rand::thread_rng();
            let random_index = rng.gen_range(0..asts_guard.len());
            let random_path = asts_guard.keys().nth(random_index);

            if let Some(path) = random_path {
                let ast = asts_guard.get(path).unwrap();
                println!("Random AST: {:?}", ast);
                println!("Initial load took {}s", original_load_time);
                println!("Parsed {} Python files", asts_len);
                println!("Visited {} lines of code", line_count);
            }
        }
    });

    println!("Watching for file changes...");
    for result in rx {
        match result {
            Ok(event) => {
                if let Event {
                    kind: notify::event::EventKind::Modify(_),
                    paths,
                    ..
                } = event
                {
                    for path in paths {
                        if path.extension().and_then(std::ffi::OsStr::to_str) == Some("py") {
                            update_ast_for_file(&path, &asts);
                        }
                    }
                }
            }
            Err(e) => println!("watch error: {:?}", e),
        }
    }
}

fn collect_paths_parallel(dir: &str) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .expect("Failed to read directory")
        .par_bridge()
        .filter_map(|entry| {
            let path = entry.expect("Failed to read entry").path();
            if path.is_dir() && path.file_name().unwrap() == "node_modules" {
                None
            } else if path.is_dir() {
                Some(collect_paths_parallel(path.to_str().unwrap()))
            } else if path.extension().and_then(std::ffi::OsStr::to_str) == Some("py") {
                Some(vec![path])
            } else {
                None
            }
        })
        .flatten()
        .collect()
}

fn parse_files_parallel(paths: &[PathBuf], asts: &Arc<Mutex<HashMap<PathBuf, Mod>>>) -> usize {
    paths
        .par_iter()
        .filter_map(|path| {
            let content = fs::read_to_string(path).ok()?;
            let lines = content.lines().count();
            match ruff_python_parser::parse(&content, ruff_python_parser::Mode::Module) {
                Ok(ast) => {
                    let mut asts_guard = asts.lock().unwrap();
                    asts_guard.insert(path.clone(), ast);
                }
                Err(_e) => (), // Handle or ignore errors as needed
            }
            Some(lines)
        })
        .sum()
}

fn update_ast_for_file(path: &PathBuf, asts: &Arc<Mutex<HashMap<PathBuf, Mod>>>) {
    println!("File changed: {:?}", path);
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            println!("Failed to read file: {:?}, error: {:?}", path, e);
            return;
        }
    };

    match ruff_python_parser::parse(&content, ruff_python_parser::Mode::Module) {
        Ok(ast) => {
            let mut asts_guard = asts.lock().unwrap();
            asts_guard.insert(path.clone(), ast);
            println!("Updated AST for {:?}", path);
        }
        Err(e) => {
            println!("Failed to parse file: {:?}, error: {:?}", path, e);
        }
    }
}
