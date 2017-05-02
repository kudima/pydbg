import struct

class Segment:
    def __init__(self, dbg, addr):
        self.address = addr
        addr += 8 # AVOID THE ENTRY ITSELF
        mem = dbg.read(addr, 0x34)

        (self.Signature, self.Flags, self.Heap, self.LargestUnCommitedRange, self.BaseAddress,
         self.NumberOfPages, self.FirstEntry, self.LastValidEntry, self.NumberOfUnCommittedPages,
         self.NumberOfUnCommittedRanges, self.UnCommittedRanges, self.AllocatorBackTraceIndex,
         self.Reserved, self.LastEntryInSegment) = struct.unpack("LLLLLLLLLLLHHL", mem)

        self.Pages = [] 
        if self.UnCommittedRanges:
            i = 0
            addr = self.UnCommittedRanges
            while addr != 0: 
                mem = dbg.read( addr,  0x10 )
                ( C_Next, C_Addr, C_Size, C_Filler) = struct.unpack( "LLLL", mem )
                self.Pages.append( C_Addr + C_Size )
                addr = C_Next

SHOWCHUNK_FULL = 0x1
CHUNK_ANALIZE  = 0x2
class win32heapchunk:
    FLAGS = { 'EXTRA PRESENT':('E', 0x2), 'FILL PATTERN':('FP', 0x4),\
              'VIRTUAL ALLOC': ('V', 0x8), 'TOP': ('T', 0x10), 
              'FFU1':('FFU1',0x20), 'FFU2': ('FFU2', 0x40),\
              'NO COALESCE':('NC', 0x80) }
    BUSY = ('BUSY', ('B', 0x1))
    def __init__(self, dbg, addr, heap = None):
        """ Win32 Chunk """
        self.dbg = dbg 

        if heap:
            self.heap_addr = heap.address
        else:
            self.heap_addr = 0
        self.nextchunk=0
        self.prevchunk=0
        self.addr = addr

        try:
            dword1 = self.get_le_uint32(addr)
            dword2 = self.get_le_uint32(addr+4)
        except Exception:
            print "failed : %08X" % (addr % 0xFFFFFFFF)
            raise Exception, "Failed to read chunk at address: 0x%08X" % addr

        self._get( dword1, dword2, addr, heap)

    def get_le_uint32(self, addr):
        return struct.unpack("<I", self.dbg.read(addr, 4))[0]

    def _get(self, size, flags, addr, heap):
        self.size   = size & 0xffff
        self.usize  = self.size * 8 # unpacked

        self.psize  = ( size >> 16 ) & 0xffff
        self.upsize = self.psize * 8

        self.field4 = flags & 0xff         
        self.flags  = (flags >> 8) & 0xff
        self.other  = (flags >> 16) & 0xffff
        mem_addr = addr + 8
        if not (self.flags & self.BUSY[1][1] ):
            if self.flags & self.FLAGS['VIRTUAL ALLOC'][1]:
                pass
            else:
                try:
                    self.nextchunk= self.get_le_uint32(addr+8)
                    self.prevchunk= self.get_le_uint32(addr+12)
                except WindowsError:
                    raise Exception, "Failed to read chunk at address: 0x%08x" % addr

                mem_addr +=8

        self.data_addr = mem_addr
        self.data_size = self.upsize - (addr - mem_addr)

        try:
            self.sample = self.dbg.read(self.data_addr, 0x10)
        except WindowsError:
            raise Exception, "Failed to read chunk at address: 0x%08x" % addr

        self.properties= {'size': self.usize, 'prevsize': self.upsize, 'field4': self.field4,\
                          'flags':self.flags, 'other':self.other, 'address':self.addr,\
                          'next': self.nextchunk, 'prev': self.prevchunk}

    def getflags(self, flag):
        f=""
        if self.flags & self.BUSY[1][1]:
            f+=self.BUSY[1][0]
        else:
            f+="F"

        for a in self.FLAGS.keys():
            if self.FLAGS[a][1] & self.flags:
                f+="|" + self.FLAGS[a][0]
        return f

    def istop(self):
        if self.flags & self.FLAGS['TOP'][1]:
            return 1
        return 0

    def isfirst(self):
        if self.psize == 0:
            return 1
        return 0

class pyheap:

    def __init__(self, dbg, heapddr = 0, full=False):
        """
        Windows 32 Heap Class

        @rtype: pyheap object
        """   
        self.dbg = dbg
        self.address  = heapddr
        self.usize = 0
        self.Segments = []
        self.chunks = []
        if heapddr:
            self._grabHeap(full)

    def _grabHeap(self, full=False):

        try:
            heaps = self.dbg.read( self.address, 0x588 )
        except WindowsError, msg:
            raise Exception, "Failed to get heap at address : 0x%08x" % self.address

        index = 0x8
        (self.Signature, self.Flags, self.ForceFlags, self.VirtualMemoryThreshold,
         self.SegmentReserve, self.SegmentCommit, self.DeCommitFreeBlockThreshold, 
         self.DeCommitTotalBlockThreshold, self.TotalFreeSize, self.MaximumAllocationSize, 
         self.ProcessHeapListIndex, self.HeaderValidateLength,
         self.HeaderValidateCopy,self.NextAvailableTagIndex, 
         self.MaximumTagIndex, self.TagEntries, self.UCRSegments, 
         self.UnusedUnCommittedRanges, self.AlignRound, self.AlignMask) =\
         struct.unpack("LLLLLLLLLLHHLHHLLLLL", heaps[ index : index + (0x50-8) ])

        index+= 0x50-8

        self.VirtualAllocedBlock  = struct.unpack("LL", heaps[ index : index + 8 ])
        index+=8

        self._Segments = struct.unpack("L" * 64, heaps[ index: index+ 64*4 ])
        index+=64*4

        self.FreeListInUseLong = struct.unpack("LLLL" , heaps[ index : index + 16 ])
        index+=16

        (self.FreeListInUseTerminate, self.AllocatorBackTraceIndex) =\
            struct.unpack("HH", heaps[ index : index + 4 ])

        index+=4
        self.Reserved1= struct.unpack("LL", heaps[ index : index + 8 ])

        index+=8
        self.PseudoTagEntries= struct.unpack("L", heaps[ index : index + 4])

        index+=4
        self.FreeList=[]

        # Getting the FreeList
        for a in range(0, 128):
            free_entry = []
            # Previous and Next Chunk of the head of the double linked list
            (prev, next) = struct.unpack("LL", heaps[ index + a*8 : index + a*8 + 8 ])

            free_entry.append((self.address + index+ a * 8, prev, next))
            base_entry = self.address + index + a * 8

            # Loop over the Double Linked List until next == to the begging of the list.
            while next != base_entry:
                tmp = next
                try:
                    (prev,next) = struct.unpack("LL",  self.dbg.read(next, 0x8))
                except:
                    break

                free_entry.append( (tmp, prev,next) )

            self.FreeList.append(free_entry)

        index+=256*4
        (self.LockVariable, self.CommitRoutine, self.Lookaside, self.LookasideLockCount)=\
         struct.unpack("LLLL", heaps[index:index+16])                     

        if full:
            # the first segment is the heap on the base address (the 2nd chunk)
            #self.Segments.
            for a in range(0, 64):
                if self._Segments[a] == 0x0:
                    break
                s = Segment( self.dbg,  self._Segments[a] )
                self.Segments.append( s )
                #imm.Log("Segment[%d]:      0x%08x" % (a, self.Segments[a]))
                # BaseAddress
                self.getChunks( s.BaseAddress )

                for idx in s.Pages:
                    self.getChunks( idx )


    def getChunks(self, address, size = 0xffffffffL):
        """
        Enumerate Chunks of the current heap

        @type  address: DWORD
        @param address: Address where to start getting chunks

        @type  size: DWORD
        @param size: (Optional, Def: All) Amount of chunks

        @rtype:  List of win32heapchunks
        @return: Chunks
        """
        ptr = address
        self.usize = 0

        while size:

            try:
                c = self.get_chunk( ptr )
            except Exception, msg:   
                self.dbg._err("Failed to grab chunks> " + str(msg) )
                return self.chunks

            self.chunks.append(c)

            ptr += c.usize
            self.usize += c.usize
            if c.istop() or c.size == 0:
                break
            size -= 1 

        return self.chunks

    def get_chunk(self,  addr):   
        return win32heapchunk(self.dbg,  addr, self)

    def get_big_chunks(self, size=0x400):
        '''
        Retrieves chunks which have size greater then 0x3F8
        '''
        ret = []

        for item in self.FreeList[0]:

            if item[0] != 0:
                chunk = self.get_chunk(item[0] - 8)
                ret.append((item[0], chunk.size))

        return ret


class win32vistaheapchunk(win32heapchunk):
    FLAGS    = { 'FILL PATTERN':('FP', 0x4), 'DEBUG': ('D', 0x8),\
                 'TOP': ('T', 0x10), 'FFU1':('FFU1',0x20),\
                 'FFU2': ('FFU2', 0x40), 'NO COALESCE':('NC', 0x80) }
    LFHMASK  = 0x3F 
    LFHFLAGS = { 'TOP': ('T', 0x3), 'BUSY': ('B', 0x18) }

    def __init__(self, dbg, addr, heap=None, BlockSize=0):

        self.heap = heap
        self.freeorder = -1
        self.isLFH = False
        if BlockSize:
            self.isLFH = True
            self.size = BlockSize
        win32heapchunk.__init__(self, dbg, addr, heap)

    def setFreeOrder(self, freeorder):
        self.freeorder = freeorder

    def _get(self, dword1, dword2, addr, heap):

        heap = self.heap            
        self.nextchunk= 0
        self.prevchunk= 0
        if heap and heap.EncodeFlagMask:
            dword1 ^= heap.EncodingKey
            dword2 = dword2 ^ heap.EncodingKey2         

        self.subsegmentcode = self.SubSegmentCode = dword1
        if self.isLFH:
            self.upsize = self.usize = self.size << 3
            self.psize = self.size
        else:
            self.size  = dword1 & 0xffff
            self.usize = self.size << 3
            self.psize  = dword2 & 0xffff
            self.upsize = self.psize << 3   

        self.flags         = (dword1 >> 16 & 0xff)
        self.smalltagindex  = (dword1 >> 24 & 0xff)

        self.segmentoffset = (dword2 >> 16 & 0xff)
        self.unused        = (dword2 >> 24 & 0xff)
        self.flags2      = self.unused # LOW FRAGMENTATION HEAP FLAGS
        self.lfhflags = self.flags2

        if not (self.flags & 0x1):
            try:
                (self.nextchunk, self.prevchunk) = struct.unpack("LL", self.dbg.read(addr+8, 8))
            except WindowsError:
                pass 

        self.data_addr = addr + 8

        self.properties= {'size': self.usize, 'prevsize': self.upsize, 'smalltagindex': self.smalltagindex,\
                          'flags':self.flags, 'subsegmentcode':self.subsegmentcode, 'address':self.addr,\
                          'next': self.nextchunk, 'prev': self.prevchunk, 'lfhflags': self.flags2,\
                          'segmentoffset': self.segmentoffset }
        self.data_size = self.usize - (self.addr - self.data_addr)

        try:
            self.sample = self.dbg.read(self.data_addr, 0x10)
        except WindowsError:
            raise Exception, "Failed to read chunk at address: 0x%08x" % addr

    def getflags(self, flag):
        f=""
        if not self.isLFH:          
            if self.flags & self.BUSY[1][1]:
                f+=self.BUSY[1][0]
            else:
                f+="F"

            for a in self.FLAGS.keys():
                if self.FLAGS[a][1] & self.flags:
                    f+="|" + self.FLAGS[a][0]
        else:
            for k in self.LFHFLAGS.keys():
                if self.flags2 == self.LFHFLAGS[k][1]:
                    return self.LFHFLAGS[k][0]
        return f

    def istop(self):
        if self.flags2 == self.LFHFLAGS['TOP'][1] : 
            return 1
        else:
            return 0    


class VistaSegment:

    def __init__(self, dbg, addr):
        
        self.address = addr
        addr += 8 # AVOID THE ENTRY ITSELF
        mem = dbg.read(addr+8, 0x38)
        
        (self.SegmentSignature, self.SegmentFlags, self.SegmentListEntry_Flink, self.SegmentListEntry_Blink,\
         self.Heap, self.BaseAddress, self.NumberOfPages, self.FirstEntry, self.LastValidEntry,\
         self.NumberofUncommitedPages, self.NumberofUncommitedRanges, self.SegmentAllocatorBackTraceIndex,\
         self.Reserved,self.UCRSegmentList_Flink,self.UCRSegmentList_Blink)=\
         struct.unpack( "L" * 11 + "HH" + "L" *2, mem)
        self.Entry =  win32vistaheapchunk(dbg, addr)

class Blocks:
    def __init__(self, dbg, addr):

        mem = dbg.read(addr, 0x24)
        if not mem:
            raise Exception, "Can't read Block at 0x%08x" % addr

        self.address = addr    
        self.FreeListInUse = None
        self.FreeList = []
        (self.ExtendedLookup, self.ArraySize, self.ExtraItem, self.ItemCount, 
         self.OutOfRangeItems, self.BaseIndex, self.ListHead,
         self.ListsInUseUlong, self.ListHints) =\
         struct.unpack( "L" * 9, mem )   

    def setFreeListInUse(self, inuse):
        self.FreeListInUse = inuse

    def setFreeList(self, flist):
        self.FreeList = flist       

class pyvistaheap(pyheap):

    LFH = None

    def __init__(self,  dbg, heapddr=0, restore=False):
        pyheap.__init__(self, dbg, heapddr, restore)
        
    def _grabHeap(self, full=False):

        try:
            heapmem = self.dbg.read(self.address + 8 , 0x120)        
        except WindowsError, msg:
            raise Exception, "Failed to get heap at address : 0x%08x" % self.address

        index = 8           
        (self.SegmentSignature, self.SegmentFlags, self.SegmentListEntry_Flink,
        self.SegmentListEntry_Blink, self.Heap, self.BaseAddress,
        self.NumberOfPages, self.FirstEntry, self.LastValidEntry,
        self.NumberofUncommitedPages, self.NumberofUncommitedRanges, 
        self.SegmentAllocatorBackTraceIndex, self.Reserved, 
        self.UCRSegmentList_Flink, self.UCRSegmentList_Blink,
        self.Flags, self.ForceFlags, self.CompatibilityFlags,
        self.EncodeFlagMask, self.EncodingKey, self.EncodingKey2,
        self.PointerKey, self.Interceptor_debug, self.VirtualMemoryThreshold,
        self.Signature, self.SegmentReserve, self.SegmentCommit,
        self.DeCommitThresholdBlock, self.DeCommitThresholdTotal, 
        self.TotalFreeSize, self.MaxAllocationSize, self.ProcessHeapsListIndex, 
        self.HeaderValidateLength, self.HeaderValidateCopy, self.NextAvailableTagIndex, 
        self.MaximumTagIndex, self.TagEntries, self.UCRList_Flink, self.UCRList_Blink,
        self.AlignRound, self.AlignMask, self.VirtualAlloc_Flink, 
        self.VirtualAlloc_Blink, self.SegmentList_Flink, self.SegmentList_Blink,
        self.AllocatorBackTraceIndex, self.NonDedicatedListLenght, self.BlocksIndex,
        self.UCRIndex, self.PseudoTagEntries, self.FreeList_Flink, 
        self.FreeList_Blink, self.LockVariable, self.CommitRoutine,
        self.FrontEndHeap, self.FrontHeapLockCount, self.FrontEndHeapType,
        self.TotalMemoryReserved, self.TotalMemoryCommited, self.TotalMemoryLargeUCR,
        self.TotalSizeInVirtualBlocks, self.TotalSegments, self.TotalUCRs,
        self.CommitOps, self.DecommitOps, self.LockAcquires, self.LockCollisions, 
        self.CommitRate, self.DeCommitRate, self.CommitFailures, 
        self.InBlockCommitFailures, self.CompactHeapCalls, self.CompactedUCRs, 
        self.InBlockDecommits, self.InBlockDecommitSize, self.TunningParameters) =\
            struct.unpack("L" * 11 + "HH" + "L" *18 + "HHLHH" + "L" * 19 + "HH" + "L" * 19, heapmem)
        head = self.address #+0x10
        addr = self.SegmentListEntry_Flink
        self.Segments.append(VistaSegment(self.dbg, self.address))
        self.getChunks(self.address)

        if addr !=0 : 
            while head != (addr& ~0xff):
                self.Segments.append( VistaSegment(self.dbg, addr - 0x10 ) )
                self.getChunks(addr  & ~0xff)
                addr = self.dbg.read_le_dword(addr)
        else:
            self.dbg._err("Error: HEAP_SEGMENT address is 0x00000000")
 
        self.FreeList = []
        self.getBlocks(self.BlocksIndex)
        # don't deal with front end yet
        #if full:
        #    if self.FrontEndHeap:
        #        if self.imm.isWin7:
        #            self.LFH = Win7LFHeap(self.imm, self.FrontEndHeap)
        #        else:
        #           self.LFH = LFHeap( self.imm, self.FrontEndHeap )

    def getBlocks(self, startaddr):
        self.blocks = []
        addr = startaddr

        while addr:
            block = Blocks(self.dbg, addr )
            self.blocks.append(block)
            block.FreeList=[]

            #calculate the number of freelists
            num_of_freelists = block.ArraySize - block.BaseIndex

            memory = self.dbg.read(block.ListHints, num_of_freelists * 8)
            #memory = self.imm.readMemory( block.Buckets, 0x80*8 )

            if block.ListsInUseUlong:      
                block.setFreeListInUse(struct.unpack("LLLL", self.dbg.read(block.ListsInUseUlong, 4*4)))

            # Getting the FreeList
            for a in range(0, num_of_freelists):
                free_entry = []
                # Previous and Next Chunk of the head of the double linked list
                (fwlink, heap_bucket) = struct.unpack("LL", memory[a *8 : a *8 + 8] )
                if fwlink:
                    try:
                        (next, prev) = struct.unpack("LL", self.dbg.read(fwlink, 8))
                    except:
                        next, prev = (0,0)
                        self.dbg._err("Error with 0x%x" % fwlink)
                    free_entry.append( (fwlink, next, prev) )               
                    base_entry = fwlink

                    while next and next != base_entry:
                        tmp = next
                        try:
                            chunk = win32vistaheapchunk(self.dbg,  next - 8, self)
                        except Exception:
                            break

                        #print("%d size: %d addr: 0x%08x 0x%08x 0x%08x" %
                        #      (a, chunk.size, next-8, chunk.nextchunk, chunk.prevchunk))

                        # it was "a == 127" initially but often there were chunks with size do 
                        # not corresponding to the bucket, and the size of the free list 
                        # is not always 127 so there is no garante that backet number 127
                        # contains "big" chunks
                        if a == num_of_freelists - 1:    
                            if chunk.size <= a:
                                break
                        else:
                            if chunk.size != a:
                                break                                       

                        next = chunk.nextchunk
                        free_entry.append( (tmp, chunk.nextchunk, chunk.prevchunk) )
                else:
                    free_entry = [(fwlink, 0x0, 0x0)]

                #if heap_bucket & 1:
                #    bucket = self.getBucket( heap_bucket - 1 )                                         
                block.FreeList.append(free_entry)

            addr = block.ExtendedLookup 

    def get_chunk(self,  addr):   
        return win32vistaheapchunk(self.dbg,  addr, self)

    def get_big_chunks(self, size=0x400):
        '''
        Retrieves chunks which have size greater then 0x3F8
        '''
        ret = []
        for block in self.blocks:

            for i in xrange(len(block.FreeList)):
                for item in block.FreeList[i]:
                    
                    if item[0] != 0:
                        chunk = self.get_chunk(item[0] - 8)
                        if chunk.size >= size:
                            ret.append((item[0], chunk.size)) 
        return ret



