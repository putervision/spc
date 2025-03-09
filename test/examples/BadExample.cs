using System;
using System.Threading;

class BadExample {
    static string ApiKey = "abc123"; // exposed_secrets

    static int Factorial(int n) { // recursion
        return Factorial(n - 1);
    }

    static void Main() {
        var list = new List<int>(100); // dynamic_memory
        while (true) { // unbounded_loops
            if (list.Count > 0) {
                if (list[0] > 0) { // nested_conditionals
                    goto End; // complex_flow (goto)
                }
            }
            Console.WriteLine(Console.ReadLine()); // unsafe_input
            Thread.Sleep(1000); // set_timeout
            return; // complex_flow (multiple returns)
        End:
            yield return 1; // complex_flow (yield)
            return;
        }
    }
}