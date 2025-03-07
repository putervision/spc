package main

import (
    "bufio"
    "crypto/md5"
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
    "os/exec"
    "time"
)

// Triggers: global_vars (global variable)
var GlobalCounter = 5

// Triggers: exposed_secrets (hardcoded secret)
var apiKey = "xyz123"

func main() {
    // Triggers: recursion (recursive call), multiple_returns (two returns)
    fmt.Println(factorial(5))

    // Triggers: dynamic_memory (make slice)
    allocateMemory()

    // Triggers: unbounded_loops (for {}), complex_flow (break)
    infiniteLoop()

    // Triggers: async_risk (go func)
    go asyncMethod()

    // Triggers: eval_usage (exec.Command)
    dynamicCode("test")

    // Triggers: nested_conditionals (nested ifs)
    nestedLogic(1, 2)

    // Triggers: unsafe_input (bufio.ReadLine), unsafe_file_op (ioutil.ReadFile)
    readInput()

    // Triggers: network_call (http.Get)
    makeNetworkCall()

    // Triggers: weak_crypto (md5.New)
    weakHash("data")

    // Triggers: unsanitized_exec (exec.Command with concatenation)
    executeCommand("test")
}

// Triggers: recursion, multiple_returns
func factorial(n int) int {
    if n <= 1 {
        return 1
    }
    return factorial(n-1) * n // Recursive call
}

// Triggers: dynamic_memory
func allocateMemory() {
    slice := make([]int, 100)
    fmt.Println(slice)
}

// Triggers: unbounded_loops, complex_flow
func infiniteLoop() {
    for {
        if GlobalCounter > 10 {
            break
        }
        GlobalCounter++
        return // Second return
    }
}

// Triggers: async_risk, set_timeout
func asyncMethod() {
    time.Sleep(1 * time.Second) // Timing-dependent
    fmt.Println("Async operation")
}

// Triggers: eval_usage
func dynamicCode(input string) {
    cmd := exec.Command("sh", "-c", input)
    cmd.Run()
}

// Triggers: nested_conditionals
func nestedLogic(x, y int) {
    if x > 0 {
        if y > 0 {
            fmt.Println("Nested condition")
        }
    }
}

// Triggers: unsafe_input, unsafe_file_op
func readInput() {
    reader := bufio.NewReader(os.Stdin)
    input, _ := reader.ReadString('\n') // Unvalidated input
    data, _ := ioutil.ReadFile("file.txt")
    fmt.Println(input, data)
}

// Triggers: network_call
func makeNetworkCall() {
    http.Get("http://api.example.com") // No error handling
}

// Triggers: weak_crypto
func weakHash(data string) {
    hash := md5.New()
    hash.Write([]byte(data))
    fmt.Println(hash.Sum(nil))
}

// Triggers: unsanitized_exec
func executeCommand(input string) {
    cmd := exec.Command("sh", "-c", "echo " + input) // Unsanitized
    cmd.Run()
}


args := os.Args                            // Triggers: os.Args (unvalidated command-line input)
data, _ := bufio.NewReader(os.Stdin).ReadString('\n') // Triggers: bufio.NewReader(...).ReadString (unvalidated stdin)
fmt.Println(args, data)                    // Use without validation