const { scanCodebase } = require('../lib/scanner');
const path = require('path');

// Mock the entire 'fs' module, including fs.promises
jest.mock('fs', () => ({
  promises: {
    readdir: jest.fn(),
    readFile: jest.fn(),
    stat: () => {
      return {
        isFile: jest.fn(() => {
          return true;
        })
      }
    },
}}));

// disable console.log
jest.spyOn(global.console, 'log').mockImplementation();

// Import fs.promises after mocking to ensure it uses the mock
const fs = require('fs').promises;

describe('scanCodebase', () => {
  beforeEach(() => {
    // Reset mocks before each test
    jest.resetAllMocks();
  });

  it('detects unbounded loops in JavaScript', async () => {
    // Mock file system
    fs.readdir.mockResolvedValue(['example.js']);
    fs.readFile.mockResolvedValue(`
      function foo() {
        while (true) {
          console.log("loop");
        }
      }
    `);

    // Mock path functions
    jest.spyOn(path, 'join').mockReturnValue('/mock/example.js');
    jest.spyOn(path, 'extname').mockReturnValue('.js');

    const results = await scanCodebase('/mock/dir');
    expect(results).toHaveLength(1);
    expect(results[0].file).toBe('/mock/example.js');
    expect(results[0].language).toBe('javascript');
    expect(results[0].issues[0].lineNum).toEqual(3);
    expect(results[0].issues[0].issueType).toContain("unbounded_loops");
    expect(results[0].issues[0].message).toContain('while (true)');
  });

  it('flags dynamic memory in Python', async () => {
    fs.readdir.mockResolvedValue(['./mocks/script.py']);
    fs.readFile.mockResolvedValue(`
      def process():
        data = list()
        return data
    `);

    jest.spyOn(path, 'join').mockReturnValue('script.py');
    jest.spyOn(path, 'extname').mockReturnValue('.py');

    const results = await scanCodebase('./mocks/');
    expect(results).toHaveLength(1);
    expect(results[0].file).toBe('script.py');
    expect(results[0].language).toBe('python');

    expect(results[0].issues[0].lineNum).toEqual(3);
    expect(results[0].issues[0].issueType).toContain("dynamic_memory");
    expect(results[0].issues[0].message).toContain('list(');

    expect(results[0].issues[1].lineNum).toEqual(4);
    expect(results[0].issues[1].issueType).toContain("complex_flow");
    expect(results[0].issues[1].message).toContain('return data');
  });

  it('catches multiple returns in C', async () => {
    fs.readdir.mockResolvedValue(['main.c']);
    fs.readFile.mockResolvedValue(`
      int compute(int x) {
        if (x > 0) return 1;
        return 0;
      }
    `);

    jest.spyOn(path, 'join').mockReturnValue('/mock/main.c');
    jest.spyOn(path, 'extname').mockReturnValue('.c');

    const results = await scanCodebase('/mock/');
    expect(results).toHaveLength(1);
    expect(results[0].file).toBe('/mock/main.c');
    expect(results[0].language).toBe('c');

    expect(results[0].issues[2].lineNum).toEqual(2);
    expect(results[0].issues[2].issueType).toContain("multiple_returns");
    expect(results[0].issues[2].message).toContain('int compute(int x)');
  });

  it('reports long functions in JavaScript', async () => {
    // Simulate a function > 60 lines
    const longFunction =
      `function big() {${'\n'} ` +
      ` console.log("x");${'\n'} `.repeat(61) +
      ' }';
    fs.readdir.mockResolvedValue(['big.js']);
    fs.readFile.mockResolvedValue(longFunction);

    // Mock path functions
    jest.spyOn(path, 'join').mockReturnValue('/mock/big.js');
    jest.spyOn(path, 'extname').mockReturnValue('.js');

    const results = await scanCodebase('/mock/');

    expect(results).toHaveLength(1);
    expect(results[0].issues[0].lineNum).toEqual(1);
    expect(results[0].issues[0].issueType).toContain("exceeds_max_func_lines");
    expect(results[0].issues[0].message).toContain(
      "Function 'big' exceeds 60 lines (63 lines)"
    );
  });

  it('ignores unsupported file types', async () => {
    fs.readdir.mockResolvedValue(['doc.txt']);
    fs.readFile.mockResolvedValue('Hello world');

    jest.spyOn(path, 'join').mockReturnValue('/mock/doc.txt');
    jest.spyOn(path, 'extname').mockReturnValue('.txt');

    const results = await scanCodebase('/mock');
    expect(results).toHaveLength(0); // No supported files
  });

  it('handles directory read errors gracefully', async () => {
    fs.readdir.mockRejectedValue(new Error('Permission denied'));
    try {
      await scanCodebase('/mock/dir');
    } catch (e) {
      expect(e.message).toEqual('Failed to scan codebase: Permission denied');
    }
  });
});

describe('security checks', () => {
  beforeEach(() => {
    jest.resetAllMocks();
  });

  it('detects unsafe input in JavaScript', async () => {
    fs.readdir.mockResolvedValue(['api.js']);
    fs.readFile.mockResolvedValue(`
      function handleRequest(req) {
        const data = req.body.payload;
        console.log(data);
      }
    `);

    jest.spyOn(path, 'join').mockReturnValue('/mock/api.js');
    jest.spyOn(path, 'extname').mockReturnValue('.js');

    const results = await scanCodebase('/mock/dir');
    expect(results[0].issues[0].lineNum).toEqual(3);
    expect(results[0].issues[0].issueType).toContain("unsafe_input");
    expect(results[0].issues[0].message).toContain('req.body');
  });

  it('flags network calls in Python', async () => {
    fs.readdir.mockResolvedValue(['net.py']);
    fs.readFile.mockResolvedValue(`
      import requests
      def fetch_data():
        response = requests.get("http://api.space")
        return response.text
    `);

    jest.spyOn(path, 'join').mockReturnValue('/mock/net.py');
    jest.spyOn(path, 'extname').mockReturnValue('.py');

    const results = await scanCodebase('/mock/dir');
    expect(results[0].issues[1].lineNum).toEqual(4);
    expect(results[0].issues[1].issueType).toContain("network_call");
    expect(results[0].issues[1].message).toContain('requests.get(');
  });

  it('catches weak crypto in C', async () => {
    fs.readdir.mockResolvedValue(['crypto.c']);
    fs.readFile.mockResolvedValue(`
      #include <stdlib.h>
      int get_random() {
        return rand();
      }
    `);

    jest.spyOn(path, 'join').mockReturnValue('/mock/crypto.c');
    jest.spyOn(path, 'extname').mockReturnValue('.c');

    const results = await scanCodebase('/mock/dir');
    expect(results[0].issues[1].lineNum).toEqual(4);
    expect(results[0].issues[1].issueType).toContain("weak_crypto");
    expect(results[0].issues[1].message).toContain('rand');
  });

  it('detects unsafe file operations in JavaScript', async () => {
    fs.readdir.mockResolvedValue(['file.js']);
    fs.readFile.mockResolvedValue(`
      const fs = require("fs");
      function readData() {
        fs.readFile("data.txt");
      }
    `);

    jest.spyOn(path, 'join').mockReturnValue('/mock/file.js');
    jest.spyOn(path, 'extname').mockReturnValue('.js');

    const results = await scanCodebase('/mock/dir');
    expect(results[0].issues[0].lineNum).toEqual(4);
    expect(results[0].issues[0].issueType).toContain("unsafe_file_op");
    expect(results[0].issues[0].message).toContain('fs.readFile("data.txt")');
  });

  it('flags insufficient logging in Python', async () => {
    fs.readdir.mockResolvedValue(['api.py']);
    fs.readFile.mockResolvedValue(`
      from flask import Flask
      app = Flask(__name__)
      @app.route("/data")
      def get_data():
        return "OK"
    `);

    jest.spyOn(path, 'join').mockReturnValue('/mock/api.py');
    jest.spyOn(path, 'extname').mockReturnValue('.py');

    const results = await scanCodebase('/mock/dir');
    expect(results[0].issues[1].lineNum).toEqual(4);
    expect(results[0].issues[1].issueType).toContain("insufficient_logging");
    expect(results[0].issues[1].message).toContain("@app.route(\"/data\")");
  });

  it('catches unsanitized execution in C', async () => {
    fs.readdir.mockResolvedValue(['exec.c']);
    fs.readFile.mockResolvedValue(`
      #include <stdlib.h>
      void run_cmd(char* input) {
        system(input);
      }
    `);

    jest.spyOn(path, 'join').mockReturnValue('/mock/exec.c');
    jest.spyOn(path, 'extname').mockReturnValue('.c');

    const results = await scanCodebase('/mock/dir');
    expect(results[0].issues[1].lineNum).toEqual(4);
    expect(results[0].issues[1].issueType).toContain("unsanitized_exec");
    expect(results[0].issues[1].message).toContain("system(input)");
  });

  it('detects exposed secrets in JavaScript', async () => {
    fs.readdir.mockResolvedValue(['secrets.js']);
    fs.readFile.mockResolvedValue(`
      const apiKey = "xyz123";
      function useKey() {
        return apiKey;
      }
    `);

    jest.spyOn(path, 'join').mockReturnValue('/mock/secrets.js');
    jest.spyOn(path, 'extname').mockReturnValue('.js');

    const results = await scanCodebase('/mock/dir');
    expect(results[0].issues[1].issueType).toContain('exposed_secrets');
    expect(results[0].issues[1].lineNum).toEqual(2);
    expect(results[0].issues[1].message).toContain(
      'const apiKey = "xyz123"'
    );
  });

  it('flags unrestricted CORS in JavaScript', async () => {
    fs.readdir.mockResolvedValue(['cors.js']);
    fs.readFile.mockResolvedValue(`
      const cors = require("cors");
      app.use(cors({ origin: "*" }));
    `);

    jest.spyOn(path, 'join').mockReturnValue('/mock/cors.js');
    jest.spyOn(path, 'extname').mockReturnValue('.js');

    const results = await scanCodebase('/mock/dir');
    expect(results[0].issues[0].lineNum).toEqual(3);
    expect(results[0].issues[0].issueType).toContain('unrestricted_cors');
    expect(results[0].issues[0].message).toContain(
      'app.use(cors({ origin: "*" })'
    );
  });

  it('catches buffer overflow risk in C', async () => {
    fs.readdir.mockResolvedValue(['buffer.c']);
    fs.readFile.mockResolvedValue(`
      #include <string.h>
      void copy(char* src) {
        char dest[10];
        strcpy(dest, src);
      }
    `);

    jest.spyOn(path, 'join').mockReturnValue('/mock/buffer.c');
    jest.spyOn(path, 'extname').mockReturnValue('.c');

    const results = await scanCodebase('/mock/dir');
    expect(results[0].issues[0].lineNum).toEqual(5);
    expect(results[0].issues[0].issueType).toEqual('buffer_overflow_risk');
    expect(results[0].issues[0].message).toContain(
      'strcpy('
    );
  });

  it('flags insufficient logging in JavaScript', async () => {
    fs.readdir.mockResolvedValue(['api.js']);
    fs.readFile.mockResolvedValue(`
      const express = require("express");
      const app = express();
      app.get("/data", function(req, res) {
        res.send("OK");
      });
    `);

    jest.spyOn(path, 'join').mockReturnValue('/mock/api.js');
    jest.spyOn(path, 'extname').mockReturnValue('.js');

    const results = await scanCodebase('/mock/dir');
    expect(results[0].issues[0].lineNum).toEqual(4);
    expect(results[0].issues[0].issueType).toEqual('insufficient_logging');
    expect(results[0].issues[0].message).toContain(
      'app.get("/data", function(req, res) {'
    );
  });

  it('flags insufficient logging in C', async () => {
    fs.readdir.mockResolvedValue(['main.c']);
    fs.readFile.mockResolvedValue(`
      #include <stdio.h>
      int main(int argc, char* argv[]) {
        int x = 5;
        return x;
      }
    `);

    jest.spyOn(path, 'join').mockReturnValue('/mock/main.c');
    jest.spyOn(path, 'extname').mockReturnValue('.c');

    const results = await scanCodebase('/mock/dir');
    expect(results[0].issues[2].lineNum).toEqual(3);
    expect(results[0].issues[2].issueType).toEqual('insufficient_logging');
    expect(results[0].issues[2].message).toContain(
      "int main(int argc, char* argv[]) {"
    );
  });

  // Verify logging prevents flagging
  it('does not flag sufficient logging in JavaScript', async () => {
    fs.readdir.mockResolvedValue(['api.js']);
    fs.readFile.mockResolvedValue(`
      const express = require("express");
      const app = express();
      app.get("/data", function(req, res) {
        console.log("Request received");
        res.send("OK");
      });
    `);

    jest.spyOn(path, 'join').mockReturnValue('/mock/api.js');
    jest.spyOn(path, 'extname').mockReturnValue('.js');

    const results = await scanCodebase('/mock/dir');
    expect(results[0].issues).not.toContain(
      expect.stringMatching(/insufficient_logging/)
    );
  });

  it('detects unchecked critical function returns in JavaScript', async () => {
    fs.readdir.mockResolvedValue(['api.js']);
    fs.readFile.mockResolvedValue(`
      function fetchData() {
        fetch("http://space.api");
      }
    `);

    jest.spyOn(path, 'join').mockReturnValue('/mock/api.js');
    jest.spyOn(path, 'extname').mockReturnValue('.js');

    const results = await scanCodebase('/mock/dir');
    expect(results[0].issues[1].message).toContain(
      'Unchecked function return - \'fetch("http://space.api");\''
    );
    expect(results[0].issues[2].message).toContain(
      'Security risk - Unchecked return from critical function - \'fetch("http://space.api");\''
    );
  });
});
