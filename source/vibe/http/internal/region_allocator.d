module vibe.http.internal.region_allocator;

public import stdx.allocator : allocatorObject, CAllocatorImpl, dispose,
	   expandArray, IAllocator, make, makeArray, shrinkArray, theAllocator;

public import stdx.allocator.gc_allocator;

final class RegionListAllocator(Allocator) : IAllocator {
    import std.typecons : Ternary;
    Allocator parent;
    Pool* pools;
    Pool* freePools;
    size_t poolSize;
    static struct Pool {
        Pool* next;
        size_t offset;
        void[] memory;

        void[] allocate(size_t size) {
            if (offset + size <= memory.length) {
                auto alloc = memory[offset..offset+size];
                offset += size;
                return alloc;
            }
            return null;
        }
    }

    this(size_t pool_size, Allocator base) @safe nothrow {
        parent = base;
        poolSize = pool_size;
        pools = null;
        freePools = null;
    }

    private void deallocatePools(Pool* poolList) {
        Pool* p = poolList;
        while (p != null) {
            auto next = p.next;
            parent.deallocate(p.memory);;
            parent.deallocate((cast(void*)p)[0..Pool.sizeof]);
            p = next;
        }
    }

    ~this() {
        deallocatePools(pools);
        deallocatePools(freePools);
    }

    override @property uint alignment() const { return 0x10; }

    static size_t alignedSize(size_t size) { return (size + 0xf) & ~0xf; }

    @property size_t totalSize()
	@safe nothrow @nogc {
		size_t amt = 0;
		for (auto p = pools; p; p = p.next)
			amt += p.memory.length;
        for (auto p = freePools; p; p = p.next)
			amt += p.memory.length;
		return amt;
	}

	@property size_t allocatedSize()
	@safe nothrow @nogc {
		size_t amt = 0;
		for (auto p = pools; p; p = p.next)
			amt += p.offset;
		return amt;
	}

    override void[] allocate(size_t sz, TypeInfo ti = null)
	{
        if (sz > poolSize) return parent.allocate(sz);
        auto size = alignedSize(sz);
        if (pools) {
            auto p = pools.allocate(size);
            if (p != null) return p[0..sz];
        }
        if (freePools) {
            auto pool = freePools;
            freePools = pool.next;
            pool.next = pools;
            pools = pool;
            auto p = pools.allocate(size);
            assert(p != null);
            return p[0..sz];
        }
        Pool* newPool = cast(Pool*)parent.allocate(Pool.sizeof).ptr;
        newPool.next = pools;
        newPool.offset = 0;
        newPool.memory = parent.allocate(poolSize);
        pools = newPool;
        auto p = pools.allocate(size);
        assert(p != null);
        return p[0..sz];
    }

    override void[] alignedAllocate(size_t n, uint a) { return null; }
	override bool alignedReallocate(ref void[] b, size_t size, uint alignment) { return false; }
	override void[] allocateAll() { return null; }
	override @property Ternary empty() const { return pools !is null ? Ternary.no : Ternary.yes; }
	override size_t goodAllocSize(size_t s) { return alignedSize(s); }

	import std.traits : Parameters;
	static if (is(Parameters!(IAllocator.resolveInternalPointer)[0] == const(void*))) {
		override Ternary resolveInternalPointer(const void* p, ref void[] result) { return Ternary.unknown; }
	} else {
		override Ternary resolveInternalPointer(void* p, ref void[] result) { return Ternary.unknown; }
	}
	static if (is(Parameters!(IAllocator.owns)[0] == const(void[]))) {
		override Ternary owns(const void[] b) { return Ternary.unknown; }
	} else {
		override Ternary owns(void[] b) { return Ternary.unknown; }
	}

    override bool reallocate(ref void[] arr, size_t newsize)
	{
		return expand(arr, newsize);
	}

	override bool expand(ref void[] arr, size_t newsize)
	{
        if (newsize < arr.length) {
            arr = arr[0..newsize];
            return true;
        }
        auto p = allocate(newsize);
        p[0..arr.length] = arr[];
        arr = p;
        return true;
    }

    override bool deallocate(void[] mem)
	{
		return false;
	}

	override bool deallocateAll()
	{
        auto p = pools;
        while(p) {
            auto next = p.next;
            p.offset = 0;
            p.next = freePools;
            freePools = p;
            p = next;
        }
        pools = null;
        return true;
    }
}

unittest {
	auto alloc = new RegionListAllocator!(shared(GCAllocator))(1024, GCAllocator.instance);
	auto mem = alloc.allocate(8);
	assert(mem.length == 8);
	alloc.deallocateAll();
    auto mem2 = alloc.allocate(8);
    assert(mem2 is mem);
}
