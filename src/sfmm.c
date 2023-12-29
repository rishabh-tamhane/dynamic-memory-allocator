/**
 * Do not submit your assignment with a main function in this file.
 * If you submit with a main function in this file, you will get a zero.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "debug.h"
#include "sfmm.h"

#define WSIZE 8
#define DSIZE 16
#define ALLOC 8
#define PALLOC  4
#define BLOCK_SIZE_REFERENCE (unsigned long)(~0xF)
#define ZERO 0
#define TWO_POW_32  4294967296

int unsigned long max_aggregate_payload;
/*Pack a size and allocated bit into a word */
#define PACK4(pld,size, alloc,palloc) ((pld)|(size)|(alloc)|(palloc))


/* Cast the pointer to 16 bytes */
#define GET(p)   (*(int *)(p))
#define PUT(p,val)   (*(long double *)(p) = val)
#define MAX(x,y)  ((x)>(y)? (x):(y))


/* Pack a size and allocated bit into a word*/
#define GET_SIZE(p)      (GET(p) & ~0xF)
#define GET_ALLOC(p)     (GET(p) & 0x1)

unsigned long find_block_size(sf_block* ptr);
unsigned long prev_alloc(sf_block* ptr);
int check_splinter(sf_block* free_list_ptr,size_t total_size);
void remove_from_free_list(sf_block * ptr);
sf_block* linked_list_search(int minimum_free_list_index,size_t total_size);
void insert_into_free_list(sf_block *ptr,int index);
int determine_free_list_index(long double size);
size_t measure_size(size_t size);
void allocate_block(sf_block* free_list_ptr,int total_size, int allocated_size);
int  check_free_ptr_validity(char * ptr);
sf_block* coalesce_back(sf_block *current_block_ptr,int set_flag);


unsigned long find_block_size(sf_block* ptr){

            debug("%lu is the size of the free block",(((*(unsigned long *)((char *)(ptr)+8))/DSIZE)*DSIZE)% 4294967296);
            return (((*(unsigned long *)((char *)(ptr)+8))/DSIZE)*DSIZE)% 4294967296;
}


unsigned long prev_alloc(sf_block* ptr){
    if((ptr->prev_footer & ALLOC)==ALLOC){
        debug("%lu is the prev footer & wsize for palloc",(ptr->prev_footer & WSIZE));
        return PALLOC;
    }
    else {
        debug("%lu is the prev footer & wsize for palloc",(ptr->prev_footer & WSIZE));
        return 0;

    }
}

int check_splinter(sf_block* free_list_ptr,size_t total_size){
    if((find_block_size(free_list_ptr)-total_size)<32)
        return 1;
    else
        return 0;
}


void remove_from_free_list(sf_block * ptr){
    sf_block * prev_ptr=ptr->body.links.prev;
    sf_block * next_ptr=ptr->body.links.next;
    prev_ptr->body.links.next=next_ptr;
    next_ptr->body.links.prev=prev_ptr;
    ptr->body.links.prev=NULL;
    ptr->body.links.next=NULL;
}



sf_block* linked_list_search(int minimum_free_list_index,size_t total_size){
    sf_block* blk_ptr;
    while(minimum_free_list_index <= 9){
        blk_ptr = sf_free_list_heads[minimum_free_list_index].body.links.next;
        while(blk_ptr != &sf_free_list_heads[minimum_free_list_index]){
            debug("%p is the blk pointer and %p is the address of sf_free_list_heads[%d]",blk_ptr,&sf_free_list_heads[minimum_free_list_index],minimum_free_list_index);
            debug("%p should be the head pointer",((char *)blk_ptr+8));
            debug("The block size is %lu",((*(unsigned long *)((char *)(blk_ptr)+8))/DSIZE)*DSIZE);
            debug("**The block size is %lu",find_block_size(blk_ptr));
            if(find_block_size(blk_ptr)>=total_size){
            debug("Found a free list at index %d and pointer %p",minimum_free_list_index,sf_free_list_heads[minimum_free_list_index].body.links.next);
            return blk_ptr;
            }
            else{
                blk_ptr=blk_ptr->body.links.next;
            }
        }

        minimum_free_list_index++;
    }

    if(minimum_free_list_index ==10){
        debug("Did not find free block and index reached %d",minimum_free_list_index);
        return NULL;
    }
    debug("Exception occuring in linked_list_search");
return NULL;  //*******address this NULL as abort maybe****
}

sf_block* coalesce_back(sf_block *current_block_ptr, int set_flag){
            unsigned long current_block_size=find_block_size(current_block_ptr);
            unsigned long previous_block_size=(((*(unsigned long *)((char *)current_block_ptr))/DSIZE)*DSIZE)% 4294967296;
            sf_block * previous_block_ptr=(sf_block *)((char *)current_block_ptr-previous_block_size);
            if(set_flag==1)
                remove_from_free_list(previous_block_ptr);
            else if(set_flag==2)
                remove_from_free_list(current_block_ptr);

            previous_block_ptr->header=PACK4(0,current_block_size+previous_block_size,0,prev_alloc(previous_block_ptr));
            sf_block * next_block_ptr=(sf_block *)((char *)current_block_ptr+current_block_size);
            next_block_ptr->prev_footer=previous_block_ptr->header;

            if((next_block_ptr->header & PALLOC) == PALLOC)
                next_block_ptr->header= (next_block_ptr->header ^ PALLOC) ;
            insert_into_free_list(previous_block_ptr,determine_free_list_index(previous_block_size+current_block_size));
            return previous_block_ptr;
}

void insert_into_free_list(sf_block *ptr,int index){
    debug("%p is the pointer of the free list",ptr);
    sf_block *block=(sf_block *)ptr;
    sf_block *sentinel=&sf_free_list_heads[index];

    block->body.links.next=sentinel->body.links.next;
    sentinel->body.links.next=block;
    (block->body.links.next)->body.links.prev=block;
    block->body.links.prev=sentinel;

    debug("Insertion into free list done for %p into list with index %d",ptr,index);
}


int determine_free_list_index(long double  size){
    size=size/(2*DSIZE);
    debug("Determining the index for %LfM",size);
    if(size <= 1){
        debug("determine_free_list_index : 0");
        return 0;
    }
    else if(size>1 && size<=2){
        debug("determine_free_list_index : 1");
        return 1;
    }
    else if(size>2 && size<=3){
        debug("determine_free_list_index : 2");
        return 2;
    }
    else if(size>3 && size<=5){
        debug("determine_free_list_index : 3");
        return 3;
    }
    else if(size>5 && size<=8){
        debug("determine_free_list_index : 4");
        return 4;
    }
    else if(size>8 && size<=13){
        debug("determine_free_list_index : 5");
        return 5;
    }
    else if(size>13 && size<=21){
        debug("determine_free_list_index : 6");
        return 6;
    }
    else if(size>21 && size<=34){
        debug("determine_free_list_index : 7");
        return 7;
    }
    else if(size>34){
        debug("determine_free_list_index : 8");
        return 8;
    }
    //wilderness condition to be taken care off while using mem_grow
return -1;
}
size_t measure_size(size_t size){
    size_t inner_block_size;
    if(((size+16)%DSIZE) >0)
        inner_block_size = ((size+16)/DSIZE)*DSIZE +DSIZE;
    else
        inner_block_size=((size+16)/DSIZE)*DSIZE ;


    //Adding 2 WSIZE for the header and footer
    return MAX(2*DSIZE,inner_block_size);
}

void allocate_block(sf_block* free_list_ptr,int total_size,int allocated_size){

    debug("removing the free block from the free list");
    sf_block * prev_free_ptr=free_list_ptr->body.links.prev;
    sf_block * next_free_ptr=free_list_ptr->body.links.next;
    prev_free_ptr->body.links.next=next_free_ptr;
    next_free_ptr->body.links.prev=prev_free_ptr;
    debug("removed the free block from the free list");
    debug("updating the tags");
    unsigned long previous_alloc=prev_alloc(free_list_ptr);
    unsigned long total_block_size=find_block_size(free_list_ptr);
    if(check_splinter(free_list_ptr,total_size)==1){
            //don't split the block
            debug("splinter possible : not splitting block");
            free_list_ptr->header=PACK4(allocated_size*TWO_POW_32,total_block_size,ALLOC,previous_alloc);
            sf_block * next_ptr = (sf_block *)((char*)free_list_ptr+total_block_size);
            next_ptr->prev_footer=free_list_ptr->header;
            next_ptr->header|=PALLOC;
        }
        else{
            //split the block and insert into the free list based on size
            debug("no splinter: splitting block");
            unsigned long remaining_size=total_block_size-total_size;
            free_list_ptr->header=PACK4(allocated_size*TWO_POW_32,total_size,ALLOC,previous_alloc);
            sf_block * new_free_ptr=(sf_block *)((char *)(free_list_ptr)+total_size);
            debug("%p is THE OLD FREE POINTER",free_list_ptr);
            debug("%p is GOING TO BE THE NEW FREE POINTER",new_free_ptr);
            debug("%lu IS THE DIFFERENCE BETWEEN NEW FREE POINTER AND OLD FREE POINTER",(unsigned long)((char*)new_free_ptr-(char*)free_list_ptr));
            new_free_ptr->prev_footer=free_list_ptr->header;
            new_free_ptr->header=PACK4(0,remaining_size,0,PALLOC);
            sf_block * next_of_new_free_ptr=(sf_block *)((char *)new_free_ptr+remaining_size);
            next_of_new_free_ptr->prev_footer=new_free_ptr->header;

            if((free_list_ptr->body.links.prev)==(&sf_free_list_heads[9]))
                insert_into_free_list(new_free_ptr,9);
            else if(remaining_size>0)
                insert_into_free_list(new_free_ptr,determine_free_list_index((long double)remaining_size));

        }
}


int  check_free_ptr_validity(char * ptr){

    if(ptr==NULL){
        debug("NULL Pointer found for free call");
        return 0;
    }
    else if(((unsigned long)ptr)%16 != 0){
        debug("Pointer is not 16 byte aligned");
        return 0;
    }
    else if(find_block_size((sf_block*)ptr) < 32){
        debug("Block Size is less than minimum block size of 32");
        return 0;
    }
    else if(((char*)ptr)<((char*)sf_mem_start()+2*DSIZE)){
        debug("Pointer is less than the first block");
        return 0;
    }
    else if(((char*)ptr)>=((char*)sf_mem_end()-2*WSIZE)){
        debug("Pointer is higher than the end block");
        return 0;
    }
    else if(((*(unsigned long *)(ptr+8))%2)!=0){
        debug("Bit 1 is not set to 0. Hence,block size is not a multiple of 16");
        return 0;
    }
    else if(((*(unsigned long *)(ptr+8))%4)!=0){
        debug("Bit 2 is not set to 0. Hence,block size is not a multiple of 16");
        return 0;
    }
    else if(((*(unsigned long *)(ptr+8))&ALLOC)!=ALLOC){
        debug("The block is not allocated.");
        return 0;
    }
    else if((((*(unsigned long *)(ptr+8))&PALLOC)==0) & (((*(unsigned long *)(ptr))&ALLOC)==ALLOC) ){
        debug("The previous block is marked not allocated in header but marked allocated in prev footer.");
        return 0;
    }
    else{
        debug("The pointer is valid for free.");
        return 1;
    }
}

void  initialise_heap(void* ptr){

    debug("Initialising the array of headers");

            for(int i=0;i<NUM_FREE_LISTS;i++){
                sf_free_list_heads[i].body.links.next=&sf_free_list_heads[i];
                sf_free_list_heads[i].body.links.prev=&sf_free_list_heads[i];
            }

    debug("array of free list headers has been initialised");

    debug("Creating prologue and epilogue");
    debug("prologue pointer: %p",ptr);

    sf_block *prologue=(sf_block *)(ptr);
    sf_block *epilogue=(sf_block *)(ptr+(PAGE_SZ-1*DSIZE));

    prologue->prev_footer=0;
    prologue->header=PACK4(ZERO,2*DSIZE,WSIZE,ZERO);

    epilogue->header=PACK4(ZERO,ZERO,ALLOC,ZERO);
    ptr+= (2*DSIZE);
    debug("The pointer is at %p",ptr);


    sf_block *first_block=(sf_block *)ptr;
    //Updating the header and footer of the rest of the block
    first_block->prev_footer=prologue->header;
    first_block->header=PACK4(ZERO,PAGE_SZ-3*DSIZE,0,PALLOC);
    epilogue->prev_footer=first_block->header;

    //Passing the rest of the block as wilderness block -create function
    debug("Inserting the pointer to the wilderness block in the last element");
    insert_into_free_list((sf_block *)ptr,9);

    //sf_show_free_lists();
    //sf_show_heap();
    debug("Initialisation of the heap ends \n");

}

unsigned long calculate_aggregate_payload(){

    unsigned long payload_size=0;
    sf_block * ptr = (sf_block *)((char*)sf_mem_start()+2*DSIZE);
    debug("While loop start for aggregate payload");
    while(ptr!=((sf_block*)((char*)sf_mem_end()-1*DSIZE))){
        debug("%p",ptr);
        if((ptr->header & ALLOC) == ALLOC){

            payload_size=payload_size + (ptr->header)/TWO_POW_32 ;

        }
        ptr =(sf_block *)((char*)ptr+find_block_size(ptr));

    }
    debug("The total payload size for allocated blocks is %lu",payload_size);

    return payload_size;
}

void *sf_malloc(size_t size) {

    debug("Received malloc request for size %lu",size);
    char *ptr;
    //Base Condition to check if the malloc request is for size 0
    if(size<=0){
        return NULL;
    }

    debug("sf_mem_start : %p",sf_mem_start());
    debug("sf_mem_end : %p",sf_mem_end());


    //If the heap is not initialized
    if(sf_mem_start()==sf_mem_end()){
        max_aggregate_payload=0;
        debug("sf_mem_start and sf_mem_end are the same. Initialisation of the heap started.");

        if((ptr=sf_mem_grow()) == NULL){
            sf_errno = ENOMEM; // Doubt: Is sf_errno already being set to ENOMEM by sf_memgrow?
            debug("ERROR : INITIALISATION : sf_mem_grow could not increase the size of the heap by 1 page");
            return NULL ;
        }
        else if(sf_mem_start()==ptr){
            debug("SUCCESS : INITIALISATION : sf_mem_grow pointer is the same as sf_mem_start. So PAGE_SZ memory added.");
            initialise_heap(ptr);
            // Initialising the array of headers doubly linked lists
        }
        else {
            error("ERROR : INITIALISATION : the previous two conditions did not satisfy..aborting");
            abort();
        }
    }

    sf_block *final_ptr;
    //Determine the size of the memory to be allocated
    debug("Determining the size to be allocated for %lu bytes which is %lu words(*8)",size,size/WSIZE);
    size_t total_size= measure_size(size) ;
    debug("SUCCESS : %lu bytes should be allocated",total_size);

    int minimum_free_list_index=determine_free_list_index((long double)total_size);
    debug("SUCCESS : %d should be the index to start looking for %lu bytes",minimum_free_list_index,total_size);

    sf_block* free_list_ptr=linked_list_search(minimum_free_list_index,total_size);
    debug("%p is the address of the free block",free_list_ptr);
    debug("%p is the sf_mem_end",sf_mem_end());
    if(free_list_ptr != NULL){
            //sf_show_free_lists();
            //sf_show_heap();
            allocate_block(free_list_ptr,total_size,size);
            final_ptr=free_list_ptr;
            debug("%p is the going to be returned to MALLOC Functions",free_list_ptr);
    }
    else {
        free_list_ptr=sf_free_list_heads[9].body.links.next;
        sf_block* new_epilogue;
        char * sbrk_ptr;
        while(find_block_size(free_list_ptr)<total_size){

            if((sbrk_ptr=sf_mem_grow())==NULL){
                sf_errno = ENOMEM;
                debug("ERROR : INITIALISATION : sf_mem_grow could not increase the size of the heap by 1 page");
                return NULL ;
            }
            else {
                sf_block* old_epilogue = (sf_block *)((char *)sbrk_ptr- DSIZE);
                if((old_epilogue->prev_footer & ALLOC) ==ALLOC){
                    debug("previous block is allocated so no coalescing required.");
                    old_epilogue->header=PACK4(0,PAGE_SZ,0,PALLOC);
                }
                else{
                    //find the pointer to the previous block
                    unsigned long previous_block_size=(((*(unsigned long *)(char *)(old_epilogue))/DSIZE)*DSIZE)% 4294967296;
                    debug("the previous block is free and size is %lu",previous_block_size);

                    sf_block* previous_free_block=(sf_block *)((char *)old_epilogue-previous_block_size);
                    //if previous block size>0
                    //update the epilogues
                    old_epilogue->header=0;   //optional
                    old_epilogue->prev_footer=0;
                    new_epilogue = (sf_block*)((char *)sf_mem_end()-1*DSIZE);
                    new_epilogue->header=PACK4(0,0,ALLOC,0);
                    remove_from_free_list(previous_free_block);
                    previous_free_block->header=PACK4(0,previous_block_size+PAGE_SZ,0,prev_alloc(previous_free_block));
                    new_epilogue->prev_footer=previous_free_block->header;
                    insert_into_free_list(previous_free_block,9);
                    free_list_ptr=previous_free_block;
                    debug(",,,,,,,,,,,,,,,,,,,,,,");

                }
                }
            }

        if(free_list_ptr != NULL){
            //sf_show_free_lists();
            //sf_show_heap();
            allocate_block(free_list_ptr,total_size,size);
            final_ptr=free_list_ptr;
        }
    }
    //sf_show_free_lists();
    //sf_show_heap();
    debug("**ENDING MALLOC**");
    debug("RETURNING THE POINTER %p to MALLOC",final_ptr);
    debug("THE FRAGMENTATION IS %f",sf_fragmentation());
    debug("The aggregate payload at this point is %lu",calculate_aggregate_payload());
    max_aggregate_payload = MAX(max_aggregate_payload,calculate_aggregate_payload());
    debug("The maximum aggregate payload till this point is %lu",max_aggregate_payload);
    debug("The peak utilization is %lf",sf_utilization());
    return (void *)((char*)final_ptr+DSIZE);
}

void sf_free(void *pp) {
    // check pointer validity
    debug("**STARTING FREE");

    if(check_free_ptr_validity(((char *)(pp)-DSIZE))==0){
            debug("Invalid Free Pointer Found");
            abort();
    }
    else{
        pp=((char *)(pp)-DSIZE);
        sf_block * ptr=(sf_block*)(pp);
        ptr->header=(ptr->header %TWO_POW_32);
        int flag=0;
        //check if the previous block is free
        if(((*(unsigned long *)((char *)pp))&ALLOC)!= ALLOC){
            debug("Free Case 1");
            flag++;
            ptr=coalesce_back(ptr,1);
        }

        sf_block * next_ptr=(sf_block*)((char*)ptr+find_block_size(ptr));

        if(((*(unsigned long *)((char*)next_ptr+8))&ALLOC)!= ALLOC){
            debug("Free Case 2");
            flag++;
            ptr=coalesce_back(next_ptr,2);
        }

        if(flag==0){
                debug("Free Case 3");
                unsigned long current_block_size=find_block_size(ptr);
                sf_block* next_ptr=(sf_block*)((char*)ptr+current_block_size);
                if((ptr->header & ALLOC) == ALLOC)
                    ptr->header= (ptr->header ^ ALLOC);
                next_ptr->prev_footer=ptr->header;
                if((next_ptr->header & PALLOC )== PALLOC)
                    next_ptr->header = (next_ptr->header ^ PALLOC);
                insert_into_free_list(ptr,determine_free_list_index(current_block_size));

        }

    }

    debug("THE FRAGMENTATION IS %f",sf_fragmentation());
    //sf_show_free_lists();
    //sf_show_heap();
    debug("The aggregate payload at this point is %lu",calculate_aggregate_payload());
    max_aggregate_payload = MAX(max_aggregate_payload,calculate_aggregate_payload());
    debug("The maximum aggregate payload till this point is %lu",max_aggregate_payload);
    debug("The peak utilization is %lf",sf_utilization());

}

void *sf_realloc(void *pp, size_t rsize) {
    // To be implemented.
    debug("Starting Realloc");
    sf_block *ptr=(sf_block*)((char *)(pp)-DSIZE);
    unsigned long current_block_size=find_block_size(ptr);
    unsigned long target_size=measure_size(rsize);
    debug("Checking Realloc Pointer Validity");
    if(check_free_ptr_validity(((char *)(pp)-DSIZE))==0){
            debug("Invalid Realloc Pointer Found");
            sf_errno=EINVAL;
            return NULL;
    }
    else if(rsize==0){
        debug("realloc block size is 0");
        sf_free(pp);
        return NULL;
    }
    else if(current_block_size<target_size){
        debug("realloc to larger size");
        void * malloc_ptr=sf_malloc(rsize);
        if(malloc_ptr==NULL)
            return NULL;
        memcpy(((char*)malloc_ptr),(char*)pp,current_block_size-DSIZE);
        //memcpy(((char*)malloc_ptr+WSIZE),(char*)pp-WSIZE,WSIZE);
        sf_block* blk_ptr = (sf_block*)((char*)malloc_ptr -DSIZE);
        blk_ptr->header=PACK4(((ptr->header)/TWO_POW_32)*TWO_POW_32,target_size,ALLOC,prev_alloc(blk_ptr));

        sf_block* next_blk_ptr= (sf_block*)((char*)blk_ptr+target_size);
        next_blk_ptr->prev_footer=blk_ptr->header;
        next_blk_ptr->header|=PALLOC;
        sf_free((char*)pp);

        debug("The aggregate payload at this point is %lu",calculate_aggregate_payload());
        max_aggregate_payload = MAX(max_aggregate_payload,calculate_aggregate_payload());
        debug("The maximum aggregate payload till this point is %lu",max_aggregate_payload);
        debug("The peak utilization is %lf",sf_utilization()); 
        return (void*)((char*)malloc_ptr);
    }

    else if(current_block_size>=target_size){
        debug("Realloc to smaller size");
        if(check_splinter(ptr,target_size)==1){
            debug("realloc splinter");
            ptr->header=PACK4(rsize*TWO_POW_32,current_block_size,ALLOC,prev_alloc(ptr));
            sf_block* tmp_ptr=(sf_block*)((char*)ptr+current_block_size);
            tmp_ptr->prev_footer=ptr->header;

            debug("The aggregate payload at this point is %lu",calculate_aggregate_payload());
            max_aggregate_payload = MAX(max_aggregate_payload,calculate_aggregate_payload());
            debug("The maximum aggregate payload till this point is %lu",max_aggregate_payload);
            debug("The peak utilization is %lf",sf_utilization());
            return (void*)pp;
        }
        else{
            ptr->header=PACK4(rsize*TWO_POW_32,target_size,ALLOC,prev_alloc(ptr));

            sf_block* new_free_ptr=(sf_block*)((char *)ptr+target_size);
            (new_free_ptr->prev_footer)=(ptr->header);

            new_free_ptr->header=PACK4(0,current_block_size-target_size,ALLOC,PALLOC);

            sf_block* next_ptr=(sf_block*)((char*)ptr+current_block_size);
            next_ptr->prev_footer=new_free_ptr->header;
            sf_free(((char*)new_free_ptr+DSIZE));


            debug("The aggregate payload at this point is %lu",calculate_aggregate_payload());
            max_aggregate_payload = MAX(max_aggregate_payload,calculate_aggregate_payload());
            debug("The maximum aggregate payload till this point is %lu",max_aggregate_payload);
            debug("The peak utilization is %lf",sf_utilization());
            return (void*)pp;

        }
    }
return NULL;
}

double sf_fragmentation() {
    long double allocated_size=0;
    long double payload_size=0;
    sf_block * ptr = (sf_block *)((char*)sf_mem_start()+2*DSIZE);
    debug("While loop start for fragmentation");
    while(ptr!=((sf_block*)((char*)sf_mem_end()-1*DSIZE))){
        debug("%p",ptr);
        if((ptr->header & ALLOC) == ALLOC){
            allocated_size+=find_block_size(ptr);

            payload_size=payload_size + (ptr->header)/TWO_POW_32 ;

        }
        ptr =(sf_block *)((char*)ptr+find_block_size(ptr));

    }
    debug("The total allocated size for allocated blocks is %Lf",allocated_size);
    debug("The total payload size for allocated blocks is %Lf",payload_size);
    debug("The peak utilization is %lf",sf_utilization()); 

    return (double)(payload_size/allocated_size);
}

double sf_utilization() {
    max_aggregate_payload = MAX(max_aggregate_payload,calculate_aggregate_payload());
    return (double)max_aggregate_payload/((double)(sf_mem_end()-sf_mem_start()));
    abort();
}
