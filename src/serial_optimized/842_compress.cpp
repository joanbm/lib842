/*
 * 842 Software Compression
 *
 * Copyright (C) 2015 Dan Streetman, IBM Corp
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * See 842.h for details of the 842 compressed format.
 */
#include "842-internal.h"
#include "../common/opcodes.h"

template<typename T> static inline void replace_hash(struct sw842_param *p, uint16_t index, uint16_t offset) {
		uint16_t ringBufferIndex = index + offset;

        switch(sizeof(T)) {
                case 2:
                        p->ringBuffer16[ringBufferIndex] = p->data[offset];
                        p->hashTable16[p->hashes[offset]] = ringBufferIndex;
                        break;
                case 4:
                        p->ringBuffer32[ringBufferIndex] = p->data[4+offset];
                        p->hashTable32[p->hashes[4+offset]] = ringBufferIndex;
                        break;
                case 8:
                        p->ringBuffer64[ringBufferIndex] = p->data[6+offset];
                        p->hashTable64[p->hashes[6+offset]] = ringBufferIndex;
                        break;
                default:
                        fprintf(stderr, "Invalid template parameter T for function replace_hash(...)\n");
        }
}

template<typename T, uint8_t OFFSET> static inline void find_index(struct sw842_param *p) {
		int16_t index;

        switch(sizeof(T)) {
                case 2:
                    index = p->hashTable16[p->hashes[OFFSET]];
                    p->validity[OFFSET] = (index >= 0) && (p->ringBuffer16[index] == p->data[OFFSET]);
           		    p->index2[OFFSET] = p->validity[OFFSET] * index;
                    switch(OFFSET) {
                        case 0:
                            p->templateKeys[OFFSET] = (13 * 3) * p->validity[OFFSET];
                            break;
                        case 1:
                            p->templateKeys[OFFSET] = (13 * 5) * p->validity[OFFSET];
                            break;
                        case 2:
                            p->templateKeys[OFFSET] = (13 * 7) * p->validity[OFFSET];
                            break;
                        case 3:
                            p->templateKeys[OFFSET] = (13 * 11) * p->validity[OFFSET];
                            break;
                    }
                	break;
                case 4:
                	index = p->hashTable32[p->hashes[4+OFFSET]];
                    p->validity[4+OFFSET] = (index >= 0) && (p->ringBuffer32[index] == p->data[4+OFFSET]);
                    p->index4[OFFSET] = p->validity[4+OFFSET] * index;
                    switch(OFFSET) {
                        case 0:
                            p->templateKeys[4+OFFSET] = (53 * 3) * p->validity[4+OFFSET];
                            break;
                        case 1:
                            p->templateKeys[4+OFFSET] = (53 * 5) * p->validity[4+OFFSET];
                            break;
                    }
                	break;
                case 8:
                	index = p->hashTable64[p->hashes[6+OFFSET]];
                    p->validity[6+OFFSET] = (index >= 0) && (p->ringBuffer64[index] == p->data[6+OFFSET]);
                    p->index8[OFFSET] = p->validity[6+OFFSET] * index;
                    p->templateKeys[6+OFFSET] = (149 * 3) * p->validity[6+OFFSET];
                    break;
        }
}

static inline uint16_t max(uint16_t a, uint16_t b) {
    return (a > b) ? a : b;
}

static inline uint8_t get_template(struct sw842_param *p) {
        uint16_t template_key = 0;

        uint16_t former = max(p->templateKeys[4], p->templateKeys[0] + p->templateKeys[1]);
        uint16_t latter = max(p->templateKeys[5], p->templateKeys[2] + p->templateKeys[3]);
        template_key = max(p->templateKeys[6], former+latter);

        template_key >>= 1;
        
        return ops_dict[template_key];
}


template<uint8_t TEMPLATE_KEY> static inline void add_template(struct sw842_param *p) {
	uint64_t out = 0;

    switch(TEMPLATE_KEY) {
        case 0x00: 	// { D8, N0, N0, N0 }, 64 bits
        	stream_write_bits(p->stream, TEMPLATE_KEY, OP_BITS);
        	stream_write_bits(p->stream, p->data[6], D8_BITS);
    	    break;
        case 0x01:	// { D4, D2, I2, N0 }, 56 bits
        	out =	(((uint64_t) TEMPLATE_KEY) << (D4_BITS + D2_BITS + I2_BITS))			|
        		 	(((uint64_t) p->data[4])  << (D2_BITS + I2_BITS)) 						|
        			(((uint64_t) p->data[2])  << (I2_BITS)) 								|
        			(((uint64_t) p->index2[3]));
        	stream_write_bits(p->stream, out, OP_BITS + D4_BITS + D2_BITS + I2_BITS);
    	    break;
        case 0x02:	// { D4, I2, D2, N0 }, 56 bits
         	out =	(((uint64_t) TEMPLATE_KEY) << (D4_BITS + I2_BITS + D2_BITS))			|
        		 	(((uint64_t) p->data[4])  << (I2_BITS + D2_BITS))						|
        		 	(((uint64_t) p->index2[2]) << (D2_BITS))								|
        		 	(((uint64_t) p->data[3]));
        	stream_write_bits(p->stream, out, OP_BITS + D4_BITS + I2_BITS + D2_BITS);
    	    break;
		case 0x03: 	// { D4, I2, I2, N0 }, 48 bits
			out =	(((uint64_t) TEMPLATE_KEY) << (D4_BITS + I2_BITS + I2_BITS))			|
        		 	(((uint64_t) p->data[4])  << (I2_BITS + I2_BITS))						|
        		 	(((uint64_t) p->index2[2]) << (I2_BITS))								|
        		 	(((uint64_t) p->index2[3]));
        	stream_write_bits(p->stream, out, OP_BITS + D4_BITS + I2_BITS + I2_BITS);
    	    break;
		case 0x04:	// { D4, I4, N0, N0 }, 41 bits
			out =	(((uint64_t) TEMPLATE_KEY) << (D4_BITS + I4_BITS))						|
        		 	(((uint64_t) p->data[4])  << (I4_BITS))								    |
        		 	(((uint64_t) p->index4[1]));
        	stream_write_bits(p->stream, out, OP_BITS + D4_BITS + I4_BITS);
    	    break;
		case 0x05:	// { D2, I2, D4, N0 }, 56 bits
			out =	(((uint64_t) TEMPLATE_KEY) << (D2_BITS + I2_BITS + D4_BITS))			|
        		 	(((uint64_t) p->data[0])  << (I2_BITS + D4_BITS))						|
        		 	(((uint64_t) p->index2[1]) << (D4_BITS))								|
        		 	(((uint64_t) p->data[5]));
        	stream_write_bits(p->stream, out, OP_BITS + D2_BITS + I2_BITS + D4_BITS); 
    	    break;
		case 0x06:	// { D2, I2, D2, I2 }, 48 bits
			out =	(((uint64_t) TEMPLATE_KEY) << (D2_BITS + I2_BITS + D2_BITS + I2_BITS))	|
        		 	(((uint64_t) p->data[0])  << (I2_BITS + D2_BITS + I2_BITS))			    |
        		 	(((uint64_t) p->index2[1]) << (D2_BITS + I2_BITS))						|
        		 	(((uint64_t) p->data[2])  << (I2_BITS))								    |
        		 	(((uint64_t) p->index2[3]));
        	stream_write_bits(p->stream, out, OP_BITS + D2_BITS + I2_BITS + D2_BITS + I2_BITS);
    	    break;
		case 0x07:	// { D2, I2, I2, D2 }, 48 bits
			out =	(((uint64_t) TEMPLATE_KEY) << (D2_BITS + I2_BITS + I2_BITS + D2_BITS))	|
        		 	(((uint64_t) p->data[0])  << (I2_BITS + I2_BITS + D2_BITS))			    |
        		 	(((uint64_t) p->index2[1]) << (I2_BITS + D2_BITS))						|
        		 	(((uint64_t) p->index2[2]) << (D2_BITS))								|
        		 	(((uint64_t) p->data[3]));
        	stream_write_bits(p->stream, out, OP_BITS + D2_BITS + I2_BITS + I2_BITS + D2_BITS);
    	    break;
		case 0x08:	// { D2, I2, I2, I2 }, 40 bits
			out =	(((uint64_t) TEMPLATE_KEY) << (D2_BITS + I2_BITS + I2_BITS + I2_BITS))	|
        		 	(((uint64_t) p->data[0])  << (I2_BITS + I2_BITS + I2_BITS))			    |
        		 	(((uint64_t) p->index2[1]) << (I2_BITS + I2_BITS))						|
        		 	(((uint64_t) p->index2[2]) << (I2_BITS))								|
        		 	(((uint64_t) p->index2[3]));
        	stream_write_bits(p->stream, out, OP_BITS + D2_BITS + I2_BITS + I2_BITS + I2_BITS);
    	    break;
		case 0x09:	// { D2, I2, I4, N0 }, 33 bits
			out =	(((uint64_t) TEMPLATE_KEY) << (D2_BITS + I2_BITS + I4_BITS))			|
        		 	(((uint64_t) p->data[0])  << (I2_BITS + I4_BITS))						|
        		 	(((uint64_t) p->index2[1]) << (I4_BITS))								|
        		 	(((uint64_t) p->index4[1]));
        	stream_write_bits(p->stream, out, OP_BITS + D2_BITS + I2_BITS + I4_BITS);
    	    break;
		case 0x0a:	// { I2, D2, D4, N0 }, 56 bits
			out =	(((uint64_t) TEMPLATE_KEY) << (I2_BITS + D2_BITS + D4_BITS))			|
        		 	(((uint64_t) p->index2[0]) << (D2_BITS + D4_BITS))						|
        		 	(((uint64_t) p->data[1])  << (D4_BITS))								    |
        		 	(((uint64_t) p->data[5]));
        	stream_write_bits(p->stream, out, OP_BITS + I2_BITS + D2_BITS + D4_BITS);
    	    break;
		case 0x0b:	// { I2, D4, I2, N0 }, 48 bits
			out =	(((uint64_t) TEMPLATE_KEY) << (I2_BITS + D4_BITS + I2_BITS))			|
        		 	(((uint64_t) p->index2[0]) << (D4_BITS + I2_BITS))						|
        		 	(((uint64_t) swap_be_to_native32(read32(p->in + 2))))  << (I2_BITS)		                    |
        		 	(((uint64_t) p->index2[3]));
        	stream_write_bits(p->stream, out, OP_BITS + I2_BITS + D4_BITS + I2_BITS);
    	    break;
		case 0x0c:	// { I2, D2, I2, D2 }, 48 bits
			out =	(((uint64_t) TEMPLATE_KEY) << (I2_BITS + D2_BITS + I2_BITS + D2_BITS))	|
        		 	(((uint64_t) p->index2[0]) << (D2_BITS + I2_BITS + D2_BITS))			|
        		 	(((uint64_t) p->data[1])  << (I2_BITS + D2_BITS))						|
        		 	(((uint64_t) p->index2[2]) << (D2_BITS))								|
        		 	(((uint64_t) p->data[3]));
        	stream_write_bits(p->stream, out, OP_BITS + I2_BITS + D2_BITS + I2_BITS + D2_BITS);
    	    break;
		case 0x0d:	// { I2, D2, I2, I2 }, 40 bits
			out =	(((uint64_t) TEMPLATE_KEY) << (I2_BITS + D2_BITS + I2_BITS + I2_BITS))	|
        		 	(((uint64_t) p->index2[0]) << (D2_BITS + I2_BITS + I2_BITS))			|
        		 	(((uint64_t) p->data[1])  << (I2_BITS + I2_BITS))						|
        		 	(((uint64_t) p->index2[2]) << (I2_BITS))								|
        		 	(((uint64_t) p->index2[3]));
        	stream_write_bits(p->stream, out, OP_BITS + I2_BITS + D2_BITS + I2_BITS + I2_BITS);
    	    break;
		case 0x0e:	// { I2, D2, I4, N0 }, 33 bits
			out =	(((uint64_t) TEMPLATE_KEY) << (I2_BITS + D2_BITS + I4_BITS))			|
        		 	(((uint64_t) p->index2[0]) << (D2_BITS + I4_BITS))						|
        		 	(((uint64_t) p->data[1])  << (I4_BITS))								    |
        		 	(((uint64_t) p->index4[1]));
        	stream_write_bits(p->stream, out, OP_BITS + I2_BITS + D2_BITS + I4_BITS);
    	    break;
		case 0x0f:	// { I2, I2, D4, N0 }, 48 bits
			out =	(((uint64_t) TEMPLATE_KEY) << (I2_BITS + I2_BITS + D4_BITS))			|
        		 	(((uint64_t) p->index2[0]) << (I2_BITS + D4_BITS))						|
        		 	(((uint64_t) p->index2[1]) << (D4_BITS))								|
        		 	(((uint64_t) p->data[5]));
        	stream_write_bits(p->stream, out, OP_BITS + I2_BITS + I2_BITS + D4_BITS);
    	    break;
		case 0x10:	// { I2, I2, D2, I2 }, 40 bits
			out =	(((uint64_t) TEMPLATE_KEY) << (I2_BITS + I2_BITS + D2_BITS + I2_BITS))	|
        		 	(((uint64_t) p->index2[0]) << (I2_BITS + D2_BITS + I2_BITS))			|
        		 	(((uint64_t) p->index2[1]) << (D2_BITS + I2_BITS))						|
        		 	(((uint64_t) p->data[2])  << (I2_BITS))								    |
        		 	(((uint64_t) p->index2[3]));
        	stream_write_bits(p->stream, out, OP_BITS + I2_BITS + I2_BITS + D2_BITS + I2_BITS);
    	    break;
		case 0x11:	// { I2, I2, I2, D2 }, 40 bits
			out =	(((uint64_t) TEMPLATE_KEY) << (I2_BITS + I2_BITS + I2_BITS + D2_BITS))	|
        		 	(((uint64_t) p->index2[0]) << (I2_BITS + I2_BITS + D2_BITS))			|
        		 	(((uint64_t) p->index2[1]) << (I2_BITS + D2_BITS))						|
        		 	(((uint64_t) p->index2[2]) << (D2_BITS))								|
        		 	(((uint64_t) p->data[3]));
        	stream_write_bits(p->stream, out, OP_BITS + I2_BITS + I2_BITS + I2_BITS + D2_BITS);
    	    break;
		case 0x12:	// { I2, I2, I2, I2 }, 32 bits
			out =	(((uint64_t) TEMPLATE_KEY) << (I2_BITS + I2_BITS + I2_BITS + I2_BITS))	|
        		 	(((uint64_t) p->index2[0]) << (I2_BITS + I2_BITS + I2_BITS))			|
        		 	(((uint64_t) p->index2[1]) << (I2_BITS + I2_BITS))						|
        		 	(((uint64_t) p->index2[2]) << (I2_BITS))								|
        		 	(((uint64_t) p->index2[3]));
        	stream_write_bits(p->stream, out, OP_BITS + I2_BITS + I2_BITS + I2_BITS + I2_BITS);
    	    break;
		case 0x13:	// { I2, I2, I4, N0 }, 25 bits
			out =	(((uint64_t) TEMPLATE_KEY) << (I2_BITS + I2_BITS + I4_BITS))			|
        		 	(((uint64_t) p->index2[0]) << (I2_BITS + I4_BITS))						|
        		 	(((uint64_t) p->index2[1]) << (I4_BITS))								|
        		 	(((uint64_t) p->index4[1]));
        	stream_write_bits(p->stream, out, OP_BITS + I2_BITS + I2_BITS + I4_BITS);
    	    break;
		case 0x14:	// { I4, D4, N0, N0 }, 41 bits
			out =	(((uint64_t) TEMPLATE_KEY) << (I4_BITS + D4_BITS))						|
        		 	(((uint64_t) p->index4[0]) << (D4_BITS))								|
        		 	(((uint64_t) p->data[5]));
        	stream_write_bits(p->stream, out, OP_BITS + I4_BITS + D4_BITS);
    	    break;
		case 0x15:	// { I4, D2, I2, N0 }, 33 bits
			out =	(((uint64_t) TEMPLATE_KEY) << (I4_BITS + D2_BITS + I2_BITS))			|
        		 	(((uint64_t) p->index4[0]) << (D2_BITS + I2_BITS))						|
        		 	(((uint64_t) p->data[2])  << (I2_BITS))								    |
        		 	(((uint64_t) p->index2[3]));
        	stream_write_bits(p->stream, out, OP_BITS + I4_BITS + D2_BITS + I2_BITS);
    	    break;
		case 0x16:	// { I4, I2, D2, N0 }, 33 bits
			out =	(((uint64_t) TEMPLATE_KEY) << (I4_BITS + I2_BITS + D2_BITS))			|
        		 	(((uint64_t) p->index4[0]) << (I2_BITS + D2_BITS))						|
        		 	(((uint64_t) p->index2[2]) << (D2_BITS))								|
        		 	(((uint64_t) p->data[3]));
        	stream_write_bits(p->stream, out, OP_BITS + I4_BITS + D2_BITS + I2_BITS);
    	    break;
		case 0x17:	// { I4, I2, I2, N0 }, 25 bits
			out =	(((uint64_t) TEMPLATE_KEY) << (I4_BITS + I2_BITS + I2_BITS))			|
        		 	(((uint64_t) p->index4[0]) << (I2_BITS + I2_BITS))						|
        		 	(((uint64_t) p->index2[2]) << (I2_BITS))								|
        		 	(((uint64_t) p->index2[3]));
        	stream_write_bits(p->stream, out, OP_BITS + I4_BITS + I2_BITS + I2_BITS);
    	    break;
		case 0x18:	// { I4, I4, N0, N0 }, 18 bits
			out =	(((uint64_t) TEMPLATE_KEY) << (I4_BITS + I4_BITS))						|
        		 	(((uint64_t) p->index4[0]) << (I4_BITS))								|
        		 	(((uint64_t) p->index4[1]));
        	stream_write_bits(p->stream, out, OP_BITS + I4_BITS + I4_BITS);
    	    break;
		case 0x19:	// { I8, N0, N0, N0 }, 8 bits
			out =	(((uint64_t) TEMPLATE_KEY) << (I8_BITS))								|
        		 	(((uint64_t) p->index8[0]));
        	stream_write_bits(p->stream, out, OP_BITS + I8_BITS);
    	    break;
        default:
        	fprintf(stderr, "Invalid template: %x\n", TEMPLATE_KEY);
        }
}

static inline void add_repeat_template(struct sw842_param *p, uint8_t r) {
	uint64_t out =	(((uint64_t) OP_REPEAT) << (REPEAT_BITS))								|
        		 	(((uint64_t) --r));

    stream_write_bits(p->stream, out, OP_BITS + REPEAT_BITS);
}

static inline void add_zeros_template(struct sw842_param *p) {
	stream_write_bits(p->stream, OP_ZEROS, OP_BITS);

}

static inline void add_end_template(struct sw842_param *p) {
	stream_write_bits(p->stream, OP_END, OP_BITS);

}

static inline void get_next_data(struct sw842_param *p) {
	p->data[6] = swap_be_to_native64(read64(p->in    ));
	p->data[4] = swap_be_to_native32(read32(p->in    ));
	p->data[5] = swap_be_to_native32(read32(p->in + 4));
	p->data[0] = swap_be_to_native16(read16(p->in    ));
	p->data[1] = swap_be_to_native16(read16(p->in + 2));
	p->data[2] = swap_be_to_native16(read16(p->in + 4));
	p->data[3] = swap_be_to_native16(read16(p->in + 6));
}

/* update the hashtable entries.
 * only call this after finding/adding the current template
 * the dataN fields for the current 8 byte block must be already updated
 */
static inline void update_hashtables(struct sw842_param *p)
{

	uint64_t pos = p->in - p->instart;
    uint16_t i64 = (pos >> 3) % (1 << BUFFER64_BITS);
    uint16_t i32 = (pos >> 2) % (1 << BUFFER32_BITS);
    uint16_t i16 = (pos >> 1) % (1 << BUFFER16_BITS);

    replace_hash<uint16_t>(p, i16, 0);
    replace_hash<uint16_t>(p, i16, 1);
    replace_hash<uint16_t>(p, i16, 2);
    replace_hash<uint16_t>(p, i16, 3);
    replace_hash<uint32_t>(p, i32, 0);
    replace_hash<uint32_t>(p, i32, 1);
    replace_hash<uint64_t>(p, i64, 0);
}

/* find the next template to use, and add it
 * the p->dataN fields must already be set for the current 8 byte block
 */
static inline void process_next(struct sw842_param *p)
{
    uint8_t templateKey;

    p->validity[0] = false;
    p->validity[1] = false;
    p->validity[2] = false;
    p->validity[3] = false;
    p->validity[4] = false;
    p->validity[5] = false;
    p->validity[6] = false;

    p->templateKeys[0] = 0;
    p->templateKeys[1] = 0;
    p->templateKeys[2] = 0;
    p->templateKeys[3] = 0;
    p->templateKeys[4] = 0;
    p->templateKeys[5] = 0;
    p->templateKeys[6] = 0;

    hashVec(p->data, p->hashes);

	find_index<uint16_t,0>(p);
	find_index<uint16_t,1>(p);
	find_index<uint16_t,2>(p);
	find_index<uint16_t,3>(p);
    find_index<uint32_t,0>(p);
    find_index<uint32_t,1>(p);
    find_index<uint64_t,0>(p);

    templateKey = get_template(p);


    switch(templateKey) {
        case 0x00: 	// { D8, N0, N0, N0 }, 64 bits
    		add_template<0x00>(p);
    	    break;
        case 0x01:	// { D4, D2, I2, N0 }, 56 bits
    		add_template<0x01>(p);
    	    break;
        case 0x02:	// { D4, I2, D2, N0 }, 56 bits
    		add_template<0x02>(p);
    	    break;
		case 0x03: 	// { D4, I2, I2, N0 }, 48 bits
    		add_template<0x03>(p);
    	    break;
		case 0x04:	// { D4, I4, N0, N0 }, 41 bits
    		add_template<0x04>(p);
    	    break;
		case 0x05:	// { D2, I2, D4, N0 }, 56 bits
    		add_template<0x05>(p);
    	    break;
		case 0x06:	// { D2, I2, D2, I2 }, 48 bits
    		add_template<0x06>(p);
    	    break;
		case 0x07:	// { D2, I2, I2, D2 }, 48 bits
    		add_template<0x07>(p);
    	    break;
		case 0x08:	// { D2, I2, I2, I2 }, 40 bits
    		add_template<0x08>(p);
    	    break;
		case 0x09:	// { D2, I2, I4, N0 }, 33 bits
    		add_template<0x09>(p);
    	    break;
		case 0x0a:	// { I2, D2, D4, N0 }, 56 bits
    		add_template<0x0a>(p);
    	    break;
		case 0x0b:	// { I2, D4, I2, N0 }, 48 bits
    		add_template<0x0b>(p);
    	    break;
		case 0x0c:	// { I2, D2, I2, D2 }, 48 bits
    		add_template<0x0c>(p);
    	    break;
		case 0x0d:	// { I2, D2, I2, I2 }, 40 bits
    		add_template<0x0d>(p);
    	    break;
		case 0x0e:	// { I2, D2, I4, N0 }, 33 bits
    		add_template<0x0e>(p);
    	    break;
		case 0x0f:	// { I2, I2, D4, N0 }, 48 bits
    		add_template<0x0f>(p);
    	    break;
		case 0x10:	// { I2, I2, D2, I2 }, 40 bits
    		add_template<0x10>(p);
    	    break;
		case 0x11:	// { I2, I2, I2, D2 }, 40 bits
    		add_template<0x11>(p);
    	    break;
		case 0x12:	// { I2, I2, I2, I2 }, 32 bits
    		add_template<0x12>(p);
    	    break;
		case 0x13:	// { I2, I2, I4, N0 }, 25 bits
    		add_template<0x13>(p);
    	    break;
		case 0x14:	// { I4, D4, N0, N0 }, 41 bits
    		add_template<0x14>(p);
    	    break;
		case 0x15:	// { I4, D2, I2, N0 }, 33 bits
    		add_template<0x15>(p);
    	    break;
		case 0x16:	// { I4, I2, D2, N0 }, 33 bits
    		add_template<0x16>(p);
    	    break;
		case 0x17:	// { I4, I2, I2, N0 }, 25 bits
    		add_template<0x17>(p);
    	    break;
		case 0x18:	// { I4, I4, N0, N0 }, 18 bits
    		add_template<0x18>(p);
    	    break;
		case 0x19:	// { I8, N0, N0, N0 }, 8 bits
    		add_template<0x19>(p);
    	    break;
        default:
        	fprintf(stderr, "Invalid template: %x\n",  templateKey);
        }
}

/**
 * sw842_compress
 *
 * Compress the uncompressed buffer of length @ilen at @in to the output buffer
 * @out, using no more than @olen bytes, using the 842 compression format.
 *
 * Returns: 0 on success, error on failure.  The @olen parameter
 * will contain the number of output bytes written on success, or
 * 0 on error.
 */
int sw842_compress(const uint8_t *in, unsigned int ilen,
		   uint8_t *out, unsigned int *olen)
{
	struct sw842_param *p = (struct sw842_param *) malloc(sizeof(struct sw842_param)); 

	uint64_t last, next;
	uint8_t repeat_count = 0;

    for(uint16_t i = 0; i < (1 << DICT16_BITS); i++) {
		p->hashTable16[i] = NO_ENTRY;
	}

    for(uint16_t i = 0; i < (1 << DICT32_BITS); i++) {
            p->hashTable32[i] = NO_ENTRY;
    }

    for(uint16_t i = 0; i < (1 << DICT64_BITS); i++) {
            p->hashTable64[i] = NO_ENTRY;
    }

	p->in = (uint8_t *)in;
	p->instart = p->in;
	p->ilen = ilen;

	p->stream = stream_open(out, *olen);

	p->olen = *olen;

	*olen = 0;
	/* if using strict mode, we can only compress a multiple of 8 */
	if (ilen % 8) {
		fprintf(stderr, "Can only compress multiples of 8 bytes, but len is len %d (%% 8 = %d)\n", ilen, ilen % 8);
		return -EINVAL;
	}

	/* make initial 'last' different so we don't match the first time */
	last = ~read64(p->in);

	while (p->ilen > 7) {
		next = read64(p->in);

		/* must get the next data, as we need to update the hashtable
		 * entries with the new data every time
		 */
		get_next_data(p);

		/* we don't care about endianness in last or next;
		 * we're just comparing 8 bytes to another 8 bytes,
		 * they're both the same endianness
		 */
		if (next == last) {
			/* repeat count bits are 0-based, so we stop at +1 */
			if (++repeat_count <= REPEAT_BITS_MAX)
				goto repeat;
		}
		if (repeat_count) {
			add_repeat_template(p, repeat_count);
			repeat_count = 0;
			if (next == last) /* reached max repeat bits */
				goto repeat;
		}

		if (next == 0)
			add_zeros_template(p);
		else
			process_next(p);

repeat:
		last = next;
		update_hashtables(p);
		p->in += 8;
		p->ilen -= 8;
	}

	if (repeat_count)
		add_repeat_template(p, repeat_count);


	add_end_template(p);

	/*
	 * crc(0:31) is appended to target data starting with the next
	 * bit after End of stream template.
	 * nx842 calculates CRC for data in big-endian format. So doing
	 * same here so that sw842 decompression can be used for both
	 * compressed data.
	 */
    #ifndef DISABLE_CRC
    uint32_t crc = crc32_be(0, (const unsigned char *) in, ilen);

	stream_write_bits(p->stream, swap_be_to_native32(crc), CRC_BITS);
    #endif

	stream_flush(p->stream);

	*olen = stream_size(p->stream);

	stream_close(p->stream);
	free(p);

	return 0;
}
