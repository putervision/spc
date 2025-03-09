val secretPassword = "pass456" // exposed_secrets

fun factorial(n: Int): Int { // recursion
    return factorial(n - 1)
}

fun main() {
    val list = mutableListOf<Int>(0, 1, 2) // dynamic_memory
    while (true) { // unbounded_loops
        if (list[0] > 0) {
            if (list[1] > 0) { // nested_conditionals
                return@forEach println(readLine()) // complex_flow (labeled return), unsafe_input
            }
        }
        Thread.sleep(1000) // set_timeout
        return // complex_flow (multiple returns)
    }
    try {
        throw Exception("Error") // try_catch
        return
    } catch (e: Exception) {
        println("Error") // insufficient_logging
    }
}