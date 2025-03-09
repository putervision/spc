program bad_example
    implicit none
    character(len=10) :: password = "secret123" ! exposed_secrets
    integer :: arr(100) ! dynamic_memory

    call factorial(5) ! recursion

contains
    recursive subroutine factorial(n) ! recursion
        integer :: n
        call factorial(n - 1)
    end subroutine factorial

    do ! unbounded_loops
        if (arr(1) > 0) then
            if (arr(2) > 0) then ! nested_conditionals
                go to 10 ! complex_flow (go to)
            end if
        end if
        read(*,*) arr(1) ! unsafe_input
        call sleep(1) ! set_timeout
        return ! complex_flow (multiple returns)
    10  stop
    end do
end program bad_example