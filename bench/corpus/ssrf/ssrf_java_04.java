// Practice sample: openStream on a request-supplied URL.
@GetMapping("/proxy")
public String proxy(@RequestParam String target) throws Exception {
    URL url = new URL(target);
    try (InputStream in = url.openStream()) {
        return new String(in.readAllBytes());
    }
}
