// Module name forced via -module-name smoke

public func hello() -> Int { return 1 }

public func add1(_ x: Int) -> Int { return x + 1 }

public func absdiff(_ a: Int, _ b: Int) -> Int {
    if a > b { return a - b }
    return b - a
}

public struct Counter {
    public var value: Int = 0
    public mutating func bump() -> Int {
        value += 1
        return value
    }
}

public func greet() -> String { return "hi" }
