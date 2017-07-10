use super::internal::Context;

#[test]
fn test_helloworld() {
    let buf = "Hello World! This tests the fuzzy hashing of a little stringy wingy.".as_bytes();

    let mut ctx = Context::new();
    ctx.update(buf);

    println!("{}", ctx.digest());
}
