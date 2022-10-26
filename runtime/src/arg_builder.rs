//don't care about performance. It's only one time shot for starting command.
pub struct ArgsBuilder {
    arg_vec: Vec<String>,
}
impl ArgsBuilder {
    pub fn new() -> ArgsBuilder {
        ArgsBuilder { arg_vec: vec![] }
    }

    pub fn get_args_vector(&self) -> Vec<String> {
        self.arg_vec.clone()
    }

    pub fn get_args_string(&self) -> String {
        self.arg_vec.join(" ")
}

    pub fn add_1(&mut self, arg: &str) {
        self.arg_vec.push(arg.to_string());
    }

    pub fn add_2(&mut self, arg1: &str, arg2: &str) {
        self.arg_vec.push(arg1.to_string());
        self.arg_vec.push(arg2.to_string());
    }

    //pub fn append_split(&mut self, split: std::str::Split<&str>) {
    //    for arg in split {
    //        self.arg_vec.push(arg.to_string())
    //    }
    //}
}
