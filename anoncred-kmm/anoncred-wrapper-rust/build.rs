use camino::Utf8Path;
use uniffi_kmm::KotlinBindingGenerator;

// Script responsible for generating a scaffold using UniFFI
fn main() {
    let out_dir = Utf8Path::new("build/generated");
    uniffi::generate_scaffolding("./src/anoncreds.udl").unwrap();
    uniffi_bindgen::generate_external_bindings(
        KotlinBindingGenerator {},
        "./src/anoncreds.udl",
        None::<&Utf8Path>,
        Some(out_dir),
    ).unwrap();
}
