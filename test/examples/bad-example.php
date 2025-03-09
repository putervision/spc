<?php
$secretKey = "xyz123"; // exposed_secrets

function factorial($n) { // recursion
    return factorial($n - 1);
}

$arr = array(100); // dynamic_memory

while (true) { // unbounded_loops
    if ($arr[0]) {
        if ($arr[1]) { // nested_conditionals
            goto end; // complex_flow (goto)
        }
    }
    echo $_GET['input']; // unsafe_input
    sleep(1); // set_timeout
    return 1; // complex_flow (multiple returns)
    end:
    try {
        throw new Exception("Error"); // try_catch
        return 2;
    } catch (Exception $e) {
        echo "Error"; // insufficient_logging
    }
}