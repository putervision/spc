object BadExample {
  val secretToken = "abc789" // exposed_secrets

  def factorial(n: Int): Int = { // recursion
    factorial(n - 1)
  }

  def main(args: Array[String]): Unit = {
    val list = List.fill(100)(0) // dynamic_memory
    while (true) { // unbounded_loops
      if (list(0) > 0) {
        if (list(1) > 0) { // nested_conditionals
          return 1 // complex_flow (multiple returns)
        }
      }
      println(scala.io.StdIn.readLine()) // unsafe_input
      Thread.sleep(1000) // set_timeout
      return 2
    }
    try {
      throw new Exception("Error") // try_catch
    } catch {
      case e: Exception => println("Error") // insufficient_logging
    }
  }
}