// Practice sample: Statement with concatenated request input.
@PostMapping("/customers/search")
public List<String> findCustomer(@RequestParam String region) throws Exception {
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery("SELECT name FROM customers WHERE region = '" + region + "'");
    List<String> out = new ArrayList<>();
    while (rs.next()) out.add(rs.getString(1));
    return out;
}
