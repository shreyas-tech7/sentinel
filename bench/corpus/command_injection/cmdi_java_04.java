// Practice sample: Runtime.exec with a concatenated request parameter.
@PostMapping("/convert")
public String convert(@RequestParam String userInput) throws IOException {
    Process proc = Runtime.getRuntime().exec("convert " + userInput + " out.png");
    return new String(proc.getInputStream().readAllBytes());
}
