module BadExample where

secretKey :: String
secretKey = "xyz456" -- exposed_secrets

factorial n = factorial (n - 1) -- recursion

main :: IO ()
main = do
    arr <- replicateM 100 getLine -- dynamic_memory, unsafe_input
    forever $ do -- unbounded_loops
        if length arr > 0
            then if arr !! 1 > "0" -- nested_conditionals
                then return "1" -- complex_flow (multiple returns)
                else return "2"
            else return "0"
        threadDelay 1000000 -- set_timeout
    catch (putStrLn "Error") (\e -> putStrLn "Caught") -- try_catch, insufficient_logging