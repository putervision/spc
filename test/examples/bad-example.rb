$global_var = 5 # global_vars
SECRET_TOKEN = "xyz789" # exposed_secrets

def factorial(n) # recursion
  factorial(n - 1)
end

arr = Array.new(100) # dynamic_memory

loop do # unbounded_loops
  if arr[0]
    if arr[1] # nested_conditionals
      retry if gets.chomp.to_i > 0 # complex_flow (retry), unsafe_input
    end
  end
  sleep 1 # set_timeout
  return 1 # complex_flow (multiple returns)
rescue
  puts "Error" # try_catch, insufficient_logging
  return 2
end