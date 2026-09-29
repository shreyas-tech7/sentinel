// Practice sample: servlet writes request value straight into the response.
@WebServlet("/greet")
public class GreetServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        PrintWriter out = resp.getWriter();
        out.println("<h1>Hello, " + name + "</h1>");
    }
}
