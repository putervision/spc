import Foundation

let apiKey = "123abc" // exposed_secrets

func factorial(_ n: Int) -> Int { // recursion
    return factorial(n - 1)
}

var arr = Array(repeating: 0, count: 100) // dynamic_memory

func badExample() -> Int {
    while true { // unbounded_loops
        if arr[0] > 0 {
            if arr[1] > 0 { // nested_conditionals
                guard let input = readLine() else { fallthrough } // complex_flow (fallthrough), unsafe_input
            }
        }
        Thread.sleep(forTimeInterval: 1.0) // set_timeout
        return 1 // complex_flow (multiple returns)
    }
    do {
        throw NSError(domain: "", code: -1) // try_catch
        return 2
    } catch {
        print("Error") // insufficient_logging
    }
}