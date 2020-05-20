/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Your student_id */
    "18307130370",
    /* Your full name */
    "贺劲洁",
    /* Your email address */
    "18307130370@fudan.edu.cn",
    /* leave blank  */
    "",
    /* leave blank */
    ""
};

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) ((((size) + (ALIGNMENT-1)) / (ALIGNMENT)) * (ALIGNMENT))

/*Basic constants and macros*/
#define WSIZE		4		/* Word and header/footer size (bytes)  */
#define DSIZE		8		/* Double word size (bytes) */

/* 每次扩展堆的块大小（系统调用“费时费力”，一次扩展一大块，然后逐渐利用这一大块） */
#define INITCHUNKSIZE (1<<6)
#define CHUNKSIZE (1<<12)   /* Extend heap by this amount (bytes)   4K  */

#define LISTMAX     16

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

/* Pack a size and allocated bit into a word */
#define PACK(size, alloc) ((size) | (alloc))

/* Read and write a word at address p */
#define GET(p)            (*(unsigned int *)(p))
#define PUT(p, val)       (*(unsigned int *)(p) = (val))	/* p是（void *）指针，把val存放在参数p只想的字中 */


#define SET_PTR(p, ptr) (*(unsigned int *)(p) = (unsigned int)(ptr))

/* Read the size and allocated fields from address p */
#define GET_SIZE(p)  (GET(p) & ~0x7)	 /* 去掉末位1（alloc标记）*/
#define GET_ALLOC(p) (GET(p) & 0x1)

/* Given block ptr bp, compute address of its header and footer */
#define HDRP(ptr) ((char *)(ptr) - WSIZE)
#define FTRP(ptr) ((char *)(ptr) + GET_SIZE(HDRP(ptr)) - DSIZE)

/*Given block ptr bp, compute address of next and previous blocks */
#define NEXT_BLKP(ptr) ((char *)(ptr) + GET_SIZE((char *)(ptr) - WSIZE))
#define PREV_BLKP(ptr) ((char *)(ptr) - GET_SIZE((char *)(ptr) - DSIZE))

#define PRED_PTR(ptr) ((char *)(ptr))			//块中祖先块指针pred的存放位置
#define SUCC_PTR(ptr) ((char *)(ptr) + WSIZE)	//后继表元  指向后继块指针存放位置的指针

#define PRED(ptr) (*(char **)(ptr))				//祖先块指针  （ptr：块指针，*ptr: 块中pred的存放位置，**ptr：pred指针指向的位置（祖先块的块指针），
#define SUCC(ptr) (*(char **)(SUCC_PTR(ptr)))	//后继块

/* 空闲链表数组 */
void *segregated_free_lists[LISTMAX];

//函数声明
/* 扩展推 */
static void *extend_heap(size_t size);
/* 合并相邻的Free block */
static void *coalesce(void *ptr);
/* 在prt所指向的free block块中allocate size大小的块，如果剩下的空间大于2*DWSIZE，则将其分离后放入Free list */
static void *place(void *ptr, size_t size);
/* 将ptr所指向的free block插入到分离空闲表中 */
static void insert_node(void *ptr, size_t size);
/* 将ptr所指向的块从分离空闲表中删除 */
static void delete_node(void *ptr);
/* 
 * mm_init - initialize the malloc package.
 */
 
static void *extend_heap(size_t size)
{
    void *ptr;
    /* 内存对齐 */
    size = ALIGN(size);
    /* 系统调用“sbrk”扩展堆 */
    if ((ptr = mem_sbrk(size)) == (void *)-1)
        return NULL;

    /* 设置刚刚扩展的free块的头和尾 */
    PUT(HDRP(ptr), PACK(size, 0));
    PUT(FTRP(ptr), PACK(size, 0));
    /* 注意这个块是堆的结尾，所以还要设置一下结尾 */
    PUT(HDRP(NEXT_BLKP(ptr)), PACK(0, 1));
    /* 设置好后将其插入到分离空闲表中 */
    insert_node(ptr, size);
    /* 另外这个free块的前面也可能是一个free块，可能需要合并 */
    return coalesce(ptr);
}

static void insert_node(void *ptr, size_t size)
{
    int listnumber = 0;
    void *search_ptr = NULL;
    void *insert_ptr = NULL;

	/* 空闲表结构
	 * | 1 | 2 | 3-4 | 5-8 |......
	     小 (SUCC)
		 |
		 v
		 大 (PRED)
	 */
	
    /* 通过块的大小找到对应的链 */
    while ((listnumber < LISTMAX - 1) && (size > 1)){
        size >>= 1;
        listnumber++;
    }

    /* 找到对应的链后，在该链中继续寻找对应的插入位置，以此保持链中块由小到大的特性 */
    search_ptr = segregated_free_lists[listnumber];
    while ((search_ptr != NULL) && (size > GET_SIZE(HDRP(search_ptr)))){
        insert_ptr = search_ptr;
        search_ptr = PRED(search_ptr);
    }
	
 /* 找到插入位置后有四种情况 */
 
    if (search_ptr != NULL){
		// 1. 在中间插入 <-> succ(insert) <-> ptr <-> pred(search) <->
        if (insert_ptr != NULL){
            SET_PTR(PRED_PTR(ptr), search_ptr);	 //search_ptr中记录着pred
            SET_PTR(SUCC_PTR(search_ptr), ptr);
            SET_PTR(SUCC_PTR(ptr), insert_ptr);
            SET_PTR(PRED_PTR(insert_ptr), ptr);
        }
        // 2. 在链表头插入，后面是空闲块 [listnumber](succ) -> ptr -> pred（search
		else{
            SET_PTR(PRED_PTR(ptr), search_ptr);
            SET_PTR(SUCC_PTR(search_ptr), ptr);
            SET_PTR(SUCC_PTR(ptr), NULL); 	//把ptr->succ 取消，断开之前的链接
            segregated_free_lists[listnumber] = ptr;
        }
    }
    else{
		// 3. 在结尾插入  <-> succ(s) <-> ptr <-> NULL
        if (insert_ptr != NULL){
            SET_PTR(PRED_PTR(ptr), NULL);
            SET_PTR(SUCC_PTR(ptr), insert_ptr);
            SET_PTR(PRED_PTR(insert_ptr), ptr);
        }
        else{
        // 4. 链表为空，[listnumber] -> ptr
            SET_PTR(PRED_PTR(ptr), NULL);
            SET_PTR(SUCC_PTR(ptr), NULL);
            segregated_free_lists[listnumber] = ptr;
        }
    }
}

/* 将ptr 所指向的块从 空闲表 中删除 */
static void delete_node(void *ptr)
{
    int listnumber = 0;
    size_t size = GET_SIZE(HDRP(ptr));

    /* 通过块的大小找到对应的链 */
    while ((listnumber < LISTMAX - 1) && (size > 1)){
        size >>= 1;
        listnumber++;
    }

    /* 根据这个块的情况分四种可能性 */
	//祖先块指针不为空
    if (PRED(ptr) != NULL){
        //1. <-> succ <-> ptr <-> pred
        if (SUCC(ptr) != NULL){
            SET_PTR(SUCC_PTR(PRED(ptr)), SUCC(ptr));
            SET_PTR(PRED_PTR(SUCC(ptr)), PRED(ptr));
        }
        //2. [listnumber] <-> ptr <-> pred <-> 
        else{
            SET_PTR(SUCC_PTR(PRED(ptr)), NULL);
            segregated_free_lists[listnumber] = PRED(ptr);
        }
    }
	//pred为空
    else{
        // 3. <->  succ <-> ptr
        if (SUCC(ptr) != NULL){  //删除node时不需要修改ptr的succ
            SET_PTR(PRED_PTR(SUCC(ptr)), NULL);
        }
        // 4. [listnumber] <-> ptr 
        else{
            segregated_free_lists[listnumber] = NULL;
        }
    }
}


static void *coalesce(void *ptr){		//书 p601
	/* !注意区分 空闲链表 中的 pred/succ 与 malloc 中的 pre_blk/next_blk
	 * 合并：合并malloc块相邻的被free的块
	 * 空闲链表相当于另外一个专门为free块按大小排序的表
	 */
	//void *next_blk = 
	size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(ptr)));	//size_t: 4 字节
	size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(ptr)));
	size_t size = GET_SIZE(HDRP(ptr));
	
	// 1. allocated -> ptr -> allocated
	if(prev_alloc && next_alloc){
		return ptr;
	}
	// 2. allocated -> ptr -> free
	else if(prev_alloc && !next_alloc){
		delete_node(ptr);
		delete_node(NEXT_BLKP(ptr));
		size += GET_SIZE(HDRP(NEXT_BLKP(ptr)));
		PUT(HDRP(ptr), PACK(size, 0));
		PUT(FTRP(ptr), PACK(size, 0));
	}
	// 3. free -> ptr -> allocated
	else if(!prev_alloc && next_alloc){
		delete_node(ptr);
		delete_node(PREV_BLKP(ptr));
		size += GET_SIZE(HDRP(PREV_BLKP(ptr)));
	    PUT(HDRP(PREV_BLKP(ptr)), PACK(size, 0));
		PUT(FTRP(ptr), PACK(size, 0));
		ptr = PREV_BLKP(ptr);		//修改块指针
	}
	// 4. free -> ptr -> free
	else{
		delete_node(ptr);
		delete_node(PREV_BLKP(ptr));
		delete_node(NEXT_BLKP(ptr));
		size += GET_SIZE(HDRP(PREV_BLKP(ptr))) + GET_SIZE(HDRP(NEXT_BLKP(ptr)));
		PUT(HDRP(PREV_BLKP(ptr)), PACK(size, 0));
        PUT(FTRP(NEXT_BLKP(ptr)), PACK(size, 0));
        ptr = PREV_BLKP(ptr);
	}
	
	/* 将合并好的 空闲块 加入到空闲链表中 */
	insert_node(ptr, size);
	return ptr;
}


/*  在ptr所指向的 空闲块 中分配size大小的块，如果剩下的空间大于 2*DSIZE （ ？） ，则将其分离后放入链表  */
static void *place(void *ptr, size_t size){
	size_t ptr_size = GET_SIZE(HDRP(ptr));
	size_t remainder = ptr_size - size;		// allocate size大小的空间后剩余的大小 
	
	delete_node(ptr);
	
	/* 如果剩余的大小小于最小块，则不分离原块 */
	if(remainder < DSIZE * 2){
		PUT(HDRP(ptr), PACK(ptr_size, 1));
		PUT(FTRP(ptr), PACK(ptr_size, 1));
	}
	/* 否则分离原块 */
	
	//有一个神奇优化，选择摘抄
	//大块往后放 (放在NEXT_BLKP)
	else if(size >= 112){   //根据binary-bal.rep和binary2-bal.rep  16/64  112/448
		PUT(HDRP(ptr), PACK(remainder, 0));
		PUT(FTRP(ptr), PACK(remainder, 0));	
		PUT(HDRP(NEXT_BLKP(ptr)), PACK(size, 1));
		PUT(FTRP(NEXT_BLKP(ptr)), PACK(size, 1));
		insert_node(ptr, remainder);
	//	coalesce(ptr);  //没用
		return NEXT_BLKP(ptr);
	}
	
	//小块往前放
	else{
		PUT(HDRP(ptr), PACK(size, 1));
		PUT(FTRP(ptr), PACK(size, 1));	
		PUT(HDRP(NEXT_BLKP(ptr)), PACK(remainder, 0));
		PUT(FTRP(NEXT_BLKP(ptr)), PACK(remainder, 0));
		insert_node(NEXT_BLKP(ptr), remainder);
	//	coalesce(NEXT_BLKP(ptr));
	}
	return ptr;	
}


int mm_init(void)
{
    int listnumber;
    char *heap; 

    /* 初始化分离空闲链表 */
    for (listnumber = 0; listnumber < LISTMAX; listnumber++)
    {
        segregated_free_lists[listnumber] = NULL;
    }

    /* 初始化堆 */
    if ((long)(heap = mem_sbrk(4 * WSIZE)) == -1)
        return -1;

    /* 这里的结构参见本文上面的“堆的起始和结束结构” */
    PUT(heap, 0);
    PUT(heap + (1 * WSIZE), PACK(DSIZE, 1));
    PUT(heap + (2 * WSIZE), PACK(DSIZE, 1));
    PUT(heap + (3 * WSIZE), PACK(0, 1));

    /* 扩展堆 */
    if (extend_heap(INITCHUNKSIZE) == NULL)
        return -1;

    return 0;
}

void *mm_malloc(size_t size)
{
    if (size == 0)
        return NULL;
    /* 内存对齐 */
    if (size <= DSIZE){
        size = 2 * DSIZE;
    }
    else{
        size = ALIGN(size + DSIZE);  //size是有效load（除去header和footer
    }

    int listnumber = 0;
    size_t searchsize = size;
    void *ptr = NULL;

    while (listnumber < LISTMAX) {
        /* 寻找对应链 */
        if (((searchsize <= 1) && (segregated_free_lists[listnumber] != NULL)))
        {
            ptr = segregated_free_lists[listnumber];
            /* 在该链寻找大小合适的free块 */
            while ((ptr != NULL) && ((size > GET_SIZE(HDRP(ptr))))){
                ptr = PRED(ptr);
            }
            /* 找到对应的free块 */
            if (ptr != NULL)
                break;
        }
        searchsize >>= 1;
        listnumber++;
    }

    /* 没有找到合适的free块，扩展堆 */
    if (ptr == NULL){
        if ((ptr = extend_heap(MAX(size, CHUNKSIZE))) == NULL)
            return NULL;
    }

    /* 在free块中allocate size大小的块 */
    ptr = place(ptr, size);

    return ptr;
}

void mm_free(void *ptr)
{
    size_t size = GET_SIZE(HDRP(ptr));

    PUT(HDRP(ptr), PACK(size, 0));
    PUT(FTRP(ptr), PACK(size, 0));

    /* 插入分离空闲链表 */
    insert_node(ptr, size);
    /* 注意合并 */
    coalesce(ptr);
}

void *mm_realloc(void *ptr, size_t size)
{
    void *new_block = ptr;
	size_t hf_size;   //加了头尾的需要的大小

    if(ptr == NULL){		//	再分配的块指针为空，同malloc
    	return mm_malloc(size);
	}
    if (size == 0){
		mm_free(ptr);
        return NULL;
	}
	//malloc的size是有效大小， place的size是size+头尾，get_size是加上头尾的大小
	/* 内存对齐 */
	if(size <= DSIZE)
		hf_size = 2 * DSIZE;  /* 一个DSIZE是header和footer， 另一个是align */
	else
		hf_size = ALIGN(size + DSIZE);
	
	size_t oldsize = GET_SIZE(HDRP(ptr)); //加了头尾
	
	/* 如果size小于原来的块的大小，直接返回原来的块 */
	if(hf_size <= oldsize){
		return ptr;
	}
	/* 该块是堆的结束块，extend因为要尽可能利用相邻的free块，以减小“external fragment 此时不找，直接extend*/
	else if(!GET_SIZE(HDRP(NEXT_BLKP(ptr)))){
		size_t remain = hf_size - oldsize;
		if(CHUNKSIZE > remain){
			remain = CHUNKSIZE;
        }
		
		if(extend_heap(remain) == NULL)	//如果差的大于默认扩展大小，差多少补多少
			return NULL;
		
		delete_node(NEXT_BLKP(ptr));    //*此时的next_blkp是刚刚extend的，extend时已经加入空闲链表，所以要删除
		
		PUT(HDRP(ptr),PACK(oldsize + remain, 1));	//直接将这个块大小置为extend后的，不分割(分了也用不到
		PUT(FTRP(ptr),PACK(oldsize + remain, 1));
	}
	//地址连续下一个块是 free 
	else if(!GET_ALLOC(HDRP(NEXT_BLKP(ptr)))){
		//够了
		if(oldsize + GET_SIZE(HDRP(NEXT_BLKP(ptr))) >= hf_size){
			size_t nx_size = oldsize + GET_SIZE(HDRP(NEXT_BLKP(ptr))) - hf_size;
			delete_node(NEXT_BLKP(ptr));  //free表中删除nx_blkp
			PUT(HDRP(ptr),PACK(hf_size, 1));
			PUT(FTRP(ptr),PACK(hf_size, 1));
			//测试后，这里分不分割无影响
			PUT(HDRP(NEXT_BLKP(ptr)), PACK(nx_size, 0));
			PUT(FTRP(NEXT_BLKP(ptr)), PACK(nx_size, 0));
		    insert_node(NEXT_BLKP(ptr),nx_size);			
		}
		//还是不够，malloc
		else{  
			new_block = mm_malloc(size);
			memcpy(new_block, ptr, GET_SIZE(HDRP(ptr)) - DSIZE);	//copy有效大小
			mm_free(ptr);
		}
	}
	
	/* 不是堆的结束块也没有一个连续的free块
	 * 没有可以利用的连续free块，而且size大于原来的块，这时只能申请新的不连续的free块，复制原快内容、释放原块 */
	else{
		new_block = mm_malloc(size);
		memcpy(new_block, ptr, GET_SIZE(HDRP(ptr)) - DSIZE);
		mm_free(ptr);
	}
	// ? else if 和 else ：为什么else if可以直接extend， else中的”原来的块“是什么
	
	return new_block;
	
}













