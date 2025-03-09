Secret = "key789" -- exposed_secrets

function factorial(n) -- recursion
    return factorial(n - 1)
end

local t = table.create(100) -- dynamic_memory

while true do -- unbounded_loops
    if t[1] then
        if t[2] then -- nested_conditionals
            goto finish -- complex_flow (goto)
        end
    end
    print(io.read()) -- unsafe_input
    os.sleep(1) -- set_timeout
    return 1 -- complex_flow (multiple returns)
    ::finish::
    pcall(function() error("Error") end) -- try_catch
    print("Error") -- insufficient_logging
    return 2
end