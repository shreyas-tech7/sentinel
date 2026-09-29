// Practice sample: File built from a request parameter.
@GetMapping("/avatar")
public byte[] avatar(@RequestParam String user) throws IOException {
    File avatarFile = new File("/srv/avatars/" + user + ".png");
    return Files.readAllBytes(avatarFile.toPath());
}
