with Ada.Text_IO; use Ada.Text_IO;

procedure Bad_Example is
   Secret_Key : constant String := "xyz123"; -- exposed_secrets

   function Factorial(N : Integer) return Integer is -- recursion
   begin
      return Factorial(N - 1); -- Unbounded recursion
   end Factorial;

   Arr : array (1 .. 100) of Integer; -- dynamic_memory
begin
   loop -- unbounded_loops
      if Arr(1) > 0 then
         if Arr(2) > 0 then -- nested_conditionals
            goto End_Label; -- complex_flow (goto)
         end if;
      end if;
      delay 1.0; -- set_timeout
      Get(Arr(1)); -- unsafe_input
      return; -- complex_flow (multiple returns)
   end loop;

exception
   when others => -- try_catch
      Put_Line("Error"); -- insufficient_logging
      return;

<<End_Label>>
end Bad_Example;