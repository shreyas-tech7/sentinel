// Clean sample: PreparedStatement, normalized+contained path, safe servlet output.
public List<String> findCustomer(Connection conn, String input) throws Exception {
    PreparedStatement ps = conn.prepareStatement("SELECT name FROM customers WHERE region = ?");
    ps.setString(1, input);
    ResultSet rs = ps.executeQuery();
    List<String> out = new ArrayList<>();
    while (rs.next()) out.add(rs.getString(1));
    return out;
}

@GetMapping("/avatar")
public byte[] avatar(@RequestParam String user) throws IOException {
    Path base = Paths.get("/srv/avatars").normalize().toAbsolutePath();
    Path target = base.resolve(user + ".png").normalize().toAbsolutePath();
    if (!target.startsWith(base)) throw new IOException("blocked");
    return Files.readAllBytes(target);
}

@WebServlet("/greet")
public class GreetServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        resp.getWriter().print("<h1>Hello, " + escapeHtml(name) + "</h1>");
    }
}
