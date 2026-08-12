# Julia bad example anti-patterns
function recursive_factorial(n::Int)
    if n <= 1
        return 1
    end
    return n * recursive_factorial(n - 1)
end

function unbounded_loop()
    while true
        println("looping")
    end
end
