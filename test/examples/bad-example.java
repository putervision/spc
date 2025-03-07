import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.concurrent.CompletableFuture;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.scheduling.annotation.Async;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;

public class BadExample {
    // Triggers: global_vars (public static variable)
    public static int globalCounter = 5;

    // Triggers: exposed_secrets (hardcoded secret)
    private String apiKey = "xyz123";

    // Triggers: recursion (recursive call), multiple_returns (two returns)
    public int factorial(int n) {
        if (n <= 1) return 1;
        return factorial(n - 1) * n; // Recursive call
    }

    // Triggers: dynamic_memory (new ArrayList), try_catch (exception handling)
    public void allocateMemory() {
        try {
            ArrayList<String> list = new ArrayList<>();
            list.add("test");
        } catch (Exception e) {
            System.out.println("Error");
        }
    }

    // Triggers: unbounded_loops (while true), complex_flow (break and return)
    public void infiniteLoop() {
        while (true) {
            if (globalCounter > 10) break;
            globalCounter++;
            return; // Second return point
        }
    }

    // Triggers: async_risk (@Async annotation), set_timeout (Thread.sleep)
    @Async
    public void asyncMethod() throws InterruptedException {
        Thread.sleep(1000); // Timing-dependent code
        System.out.println("Async operation");
    }

    // Triggers: eval_usage (ScriptEngine.eval)
    public void dynamicCode() throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");
        engine.eval("print('Hello');"); // Dynamic code execution
    }

    // Triggers: nested_conditionals (nested ifs)
    public void nestedLogic(int x, int y) {
        if (x > 0) {
            if (y > 0) {
                System.out.println("Nested condition");
            }
        }
    }

    // Triggers: unsafe_input (BufferedReader.readLine), unsafe_file_op (FileReader)
    public void readInput() throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader("file.txt"));
        String input = reader.readLine(); // Unvalidated input from file
        reader.close();
    }

    // Triggers: network_call (HttpURLConnection), critical_functions (connect not checked)
    public void makeNetworkCall() throws IOException {
        URL url = new URL("http://api.example.com");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.connect(); // Return not checked
    }

    // Triggers: weak_crypto (MD5 usage)
    public byte[] weakHash(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data.getBytes());
    }

    // Triggers: unsanitized_exec (Runtime.exec with concatenation)
    public void executeCommand(String userInput) throws IOException {
        Runtime.getRuntime().exec("cmd " + userInput); // Unsanitized execution
    }

    // Triggers: insufficient_logging (no logging in endpoint), unrestricted_cors (@CrossOrigin with "*")
    @CrossOrigin(origins = "*")
    @GetMapping("/data")
    public void handleRequest(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String data = req.getParameter("payload"); // Triggers: unsafe_input
        resp.getWriter().write("OK"); // No logging
    }

    // Main method to trigger some patterns
    public static void main(String[] args) throws Exception {
        BadExample example = new BadExample();
        example.factorial(5);           // Recursion
        example.allocateMemory();       // Dynamic memory
        example.infiniteLoop();         // Unbounded loop
        example.asyncMethod();          // Async risk
        example.dynamicCode();          // Eval usage
        example.nestedLogic(1, 2);      // Nested conditionals
        example.readInput();            // Unsafe input/file op
        example.makeNetworkCall();      // Network call
        example.weakHash("data");       // Weak crypto
        example.executeCommand("test"); // Unsanitized exec
    }
}


String param = request.getParameter("key");   // Triggers: request.getParameter (unvalidated)
String input = new BufferedReader(new InputStreamReader(System.in)).readLine(); // Triggers: BufferedReader.readLine (unvalidated)
System.out.println(param + input);            // Use without validation