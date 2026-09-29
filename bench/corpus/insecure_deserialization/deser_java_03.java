// Practice sample (WebGoat-style): base64 token into ObjectInputStream.
@PostMapping("/deserialize")
public AttackResult completed(@RequestParam String token) throws Exception {
    byte[] data = Base64.getDecoder().decode(token);
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
    Object o = ois.readObject();
    return report(o);
}
