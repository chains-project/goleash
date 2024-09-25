# Monkey Patching in Go
Let’s look at what the following code produces when disassembled:

```go
package main

func a() int { return 1 }

func main() {
  print(a())
}
```

When compiled and looked at through Hopper, the above code will produce this assembly code:
[figure_Assembly]

I will be referring to the addresses of the various instructions displayed on the left side of the screen.

Our code starts in procedure main.main, where instructions 0x2010 to 0x2026 set up the stack. You can read more about that here, I will be ignoring that code for the rest of the article.

Line 0x202a is the call to function main.a at line 0x2000 which simply moves 0x1 onto the stack and returns. Lines 0x202f to 0x2037 then pass that value on to runtime.printint.

Simple enough! Now let’s take a look at how function values are implemented in Go.

## How function values work in Go
Consider the following code:

```go
package main

import (
  "fmt"
  "unsafe"
)

func a() int { return 1 }

func main() {
  f := a
  fmt.Printf("0x%x\n", *(*uintptr)(unsafe.Pointer(&f)))
}
```

What I’m doing on line 11 is assigning a to f, which means that doing f() will now call a. Then I use the unsafe Go package to directly read out the value stored in f. If you come from a C background you might expect f to simply be a function pointer to a and thus this code to print out 0x2000 (the location of main.a as we saw above). When I run this on my machine I get 0x102c38, which is an address not even close to our code! When disassembled, this is what happens on line 11 above:

[figure_Assembly]

This references something called main.a.f, and when we look at that location, we see this:

[figure assembly]

Aha! main.a.f is at 0x102c38 and contains 0x2000, which is the location of main.a. It seems f isn’t a pointer to a function, but a pointer to a pointer to a function. Let’s modify the code to compensate for that.


```go
package main
 
import (
  "fmt"
  "unsafe"
)
 
func a() int { return 1 }
 
func main() {
  f := a
  fmt.Printf("0x%x\n", **(**uintptr)(unsafe.Pointer(&f)))
}
```

This will now print 0x2000, as expected. We can find a clue as to why this is implemented as it is here. Go function values can contain extra information, which is how closures and bound instance methods are implemented.

Let’s look at how calling a function value works. I’ll change the code to call f after assigning it.


```go
package main

func a() int { return 1 }

func main() {
	f := a
	f()
}
```

When we disassemble this we get the following:

[figure_Assembly]

main.a.f gets loaded into rdx, then whatever rdx points at gets loaded into rbx, which then gets called. The address of the function value always gets loaded into rdx, which the code being called can use to load any extra information it might need. This extra information is a pointer to the instance for a bound instance method and the closure for an anonymous function. I advise you to take out a disassembler and dive deeper if you want to know more!

Let’s use our newly gained knowledge to implement monkeypatching in Go.

## Replacing a function at runtime

What we want to achieve is to have the following code print out 2:

```go
package main

func a() int { return 1 }
func b() int { return 2 }

func main() {
	replace(a, b)
	print(a())
}
```

Now how do we implement replace? We need to modify function a to jump to b’s code instead of executing its own body. Essentialy, we need to replace it with this, which loads the function value of b into rdx and then jumps to the location pointed to by rdx.

```assembly
mov rdx, main.b.f ; 48 C7 C2 ?? ?? ?? ??
jmp [rdx] ; FF 22
```

I’ve put the corresponding machine code that those lines generate when assembled next to it (you can easily play around with assembly using an online assembler like this). Writing a function that will generate this code is now straightforward, and looks like this:

```go
func assembleJump(f func() int) []byte {
  funcVal := *(*uintptr)(unsafe.Pointer(&f))
  return []byte{
    0x48, 0xC7, 0xC2,
    byte(funcval >> 0),
    byte(funcval >> 8),
    byte(funcval >> 16),
    byte(funcval >> 24), // MOV rdx, funcVal
    0xFF, 0x22,          // JMP [rdx]
  }
}
```

We now have everything we need to replace a’s function body with a jump to b! The following code attempts to copy the machine code directly to the location of the function body.

```go
package main

import (
	"syscall"
	"unsafe"
)

func a() int { return 1 }
func b() int { return 2 }

func rawMemoryAccess(b uintptr) []byte {
	return (*(*[0xFF]byte)(unsafe.Pointer(b)))[:]
}

func assembleJump(f func() int) []byte {
	funcVal := *(*uintptr)(unsafe.Pointer(&f))
	return []byte{
		0x48, 0xC7, 0xC2,
		byte(funcVal >> 0),
		byte(funcVal >> 8),
		byte(funcVal >> 16),
		byte(funcVal >> 24), // MOV rdx, funcVal
		0xFF, 0x22,          // JMP [rdx]
	}
}

func replace(orig, replacement func() int) {
	bytes := assembleJump(replacement)
	functionLocation := **(**uintptr)(unsafe.Pointer(&orig))
	window := rawMemoryAccess(functionLocation)
	
	copy(window, bytes)
}

func main() {
	replace(a, b)
	print(a())
}
```

Running this code does not work however, and will result in a segmentation fault. This is because the loaded binary is not writable by default. We can use the mprotect syscall to disable this protection, and this final version of the code does exactly that, resulting in function a being replaced by function b, and ‘2’ being printed.

```go
package main

import (
	"syscall"
	"unsafe"
)

func a() int { return 1 }
func b() int { return 2 }

func getPage(p uintptr) []byte {
	return (*(*[0xFFFFFF]byte)(unsafe.Pointer(p & ^uintptr(syscall.Getpagesize()-1))))[:syscall.Getpagesize()]
}

func rawMemoryAccess(b uintptr) []byte {
	return (*(*[0xFF]byte)(unsafe.Pointer(b)))[:]
}

func assembleJump(f func() int) []byte {
	funcVal := *(*uintptr)(unsafe.Pointer(&f))
	return []byte{
		0x48, 0xC7, 0xC2,
		byte(funcVal >> 0),
		byte(funcVal >> 8),
		byte(funcVal >> 16),
		byte(funcVal >> 24), // MOV rdx, funcVal
		0xFF, 0x22,          // JMP rdx
	}
}

func replace(orig, replacement func() int) {
	bytes := assembleJump(replacement)
	functionLocation := **(**uintptr)(unsafe.Pointer(&orig))
	window := rawMemoryAccess(functionLocation)
	
	page := getPage(functionLocation)
	syscall.Mprotect(page, syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC)
	
	copy(window, bytes)
}

func main() {
	replace(a, b)
	print(a())
}
```