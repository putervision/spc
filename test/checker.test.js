const { scanCodebase } = require("../lib/checker");
const path = require("path");

// Mock the entire 'fs' module, including fs.promises
jest.mock("fs", () => ({
  promises: {
    readdir: jest.fn(),
    readFile: jest.fn(),
  },
}));

// Import fs.promises after mocking to ensure it uses the mock
const fs = require("fs").promises;

describe("scanCodebase", () => {
  beforeEach(() => {
    // Reset mocks before each test
    jest.resetAllMocks();
  });

  it("detects unbounded loops in JavaScript", async () => {
    // Mock file system
    fs.readdir.mockResolvedValue(["example.js"]);
    fs.readFile.mockResolvedValue(`
      function foo() {
        while (true) {
          console.log("loop");
        }
      }
    `);

    // Mock path functions
    jest.spyOn(path, "join").mockReturnValue("/mock/example.js");
    jest.spyOn(path, "extname").mockReturnValue(".js");

    const results = await scanCodebase("/mock/dir");
    expect(results).toHaveLength(1);
    expect(results[0].file).toBe("/mock/example.js");
    expect(results[0].language).toBe("javascript");
    expect(results[0].issues).toContain(
      "Line 3: unbounded_loops detected - 'while (true)'"
    );
  });

  it("flags dynamic memory in Python", async () => {
    fs.readdir.mockResolvedValue(["./mocks/script.py"]);
    fs.readFile.mockResolvedValue(`
      def process():
        data = list()
        return data
    `);

    jest.spyOn(path, "join").mockReturnValue("script.py");
    jest.spyOn(path, "extname").mockReturnValue(".py");

    const results = await scanCodebase("./mocks/");
    expect(results).toHaveLength(1);
    expect(results[0].file).toBe("script.py");
    expect(results[0].language).toBe("python");
    expect(results[0].issues[0]).toContain(
        "Line 3: dynamic_memory detected - 'list('"
    );
    expect(results[0].issues[1]).toContain(
        "Line 4: complex_flow detected - 'return data'"
    );
  });

  it("catches multiple returns in C", async () => {
    fs.readdir.mockResolvedValue(["main.c"]);
    fs.readFile.mockResolvedValue(`
      int compute(int x) {
        if (x > 0) return 1;
        return 0;
      }
    `);

    jest.spyOn(path, "join").mockReturnValue("/mock/main.c");
    jest.spyOn(path, "extname").mockReturnValue(".c");

    const results = await scanCodebase("/mock/");
    expect(results).toHaveLength(1);
    expect(results[0].file).toBe("/mock/main.c");
    expect(results[0].language).toBe("c");
    expect(results[0].issues[2]).toContain(
      "Line 2: multiple_returns detected - 'int compute(int x)"
    );
  });

  it("reports long functions in JavaScript", async () => {
    // Simulate a function > 60 lines
    const longFunction = `function big() {${'\n'} ` + ` console.log("x");${'\n'} `.repeat(61) + " }";
    fs.readdir.mockResolvedValue(["big.js"]);
    fs.readFile.mockResolvedValue(longFunction);

    // Mock path functions
    jest.spyOn(path, "join").mockReturnValue("/mock/big.js");
    jest.spyOn(path, "extname").mockReturnValue(".js");

    const results = await scanCodebase("/mock/");
    
    expect(results).toHaveLength(1);
    expect(results[0].issues[0]).toContain(
      "Line 1: Function 'big' exceeds 60 lines (63 lines)"
    );
  });

  it("ignores unsupported file types", async () => {
    fs.readdir.mockResolvedValue(["doc.txt"]);
    fs.readFile.mockResolvedValue("Hello world");

    jest.spyOn(path, "join").mockReturnValue("/mock/doc.txt");
    jest.spyOn(path, "extname").mockReturnValue(".txt");

    const results = await scanCodebase("/mock");
    expect(results).toHaveLength(0); // No supported files
  });

  it("handles directory read errors gracefully", async () => {
    fs.readdir.mockRejectedValue(new Error("Permission denied"));
    try {
        await scanCodebase("/mock/dir")
    } catch (e) {
        expect(e.message).toEqual(
            "Failed to scan codebase: Permission denied"
        )
    }
  });
});