/*******************************************************************************
*   (c) 2018 Zondax GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
#include "zxmacros.h"

#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"

void handle_stack_overflow() {
    zemu_log("!!!!!!!!!!!!!!!!!!!!!! CANARY TRIGGERED!!! STACK OVERFLOW DETECTED\n");
#if defined (TARGET_NANOS) || defined(TARGET_NANOX) || defined(TARGET_NANOS2)
    io_seproxyhal_se_reset();
#else
    while (1);
#endif
}

#pragma clang diagnostic pop

__Z_UNUSED void check_app_canary() {
#if defined (TARGET_NANOS) || defined(TARGET_NANOX) || defined(TARGET_NANOS2)
    if (app_stack_canary != APP_STACK_CANARY_MAGIC) handle_stack_overflow();
#endif
}

#if defined(ZEMU_LOGGING) && (defined (TARGET_NANOS) || defined(TARGET_NANOX) || defined(TARGET_NANOS2))
void zemu_log_stack(const char *ctx) {
    #define STACK_SHIFT 20
    void* p = NULL;
    char buf[70];
    snprintf(buf, sizeof(buf), "|SP| %p %p (%d) : %s\n",
            &app_stack_canary,
            ((void*)&p)+STACK_SHIFT,
            (uint32_t)((void*)&p)+STACK_SHIFT - (uint32_t)&app_stack_canary,
            ctx);
    zemu_log(buf);
    (void) ctx;
}
#else

void zemu_log_stack(__Z_UNUSED const char *ctx) {}

#endif

#if defined(ZEMU_LOGGING) && (defined (TARGET_NANOS) || defined(TARGET_NANOX) || defined(TARGET_NANOS2))
static void x64toa(unsigned long long val, char *buf, unsigned radix, int is_neg)
{
    char *p;
    char *firstdig;
    char temp;
    unsigned digval;
    p = buf; *p=0,p[1]='\0';
    if (val==0||radix<2||radix>32||radix&1) return;
    if ( is_neg )  *p++ = '-', val = (unsigned long long)(-(long long)val);
    firstdig = p;
    if(radix--==10)
        do { // optimized for fixed division
            digval = (unsigned) (val % 10);
            val /= 10;
            *p++ = (char) (digval + '0');
        } while (val > 0);
    else do { temp=radix;
            digval = (unsigned) (val & radix );
            while(temp) val>>=1,temp>>=1;
            *p++ = digval>9?(char)(digval + 'W'):(char) (digval + '0');
        } while (val>0);
    *p-- = '\0';
    do { // reverse string
        temp = *p;
        *p = *firstdig;
        *firstdig = temp;
        --p;
        ++firstdig;
    } while (firstdig < p);
}
//----------------------------------------------------------------------------
char* l2s(long long v,int sign) { char r,s;
    static char buff[33];  r=sign>>8; s=sign;
    if(!r)
        r=10;
    if((r!=10)||(s&&v>=0))
        s=0;
    if(r<8)
        r=0;
    x64toa(v,buff,r,s); return buff;
}


void zemu_log_stack_uint64(uint64_t val) {
    #define STACK_SHIFT 20
    char buf[70];
    snprintf(buf, sizeof(buf), "%s \n",l2s(val,0));
    zemu_log(buf);
    (void) val;
}

void zemu_log_stack_int64(int64_t val) {
    #define STACK_SHIFT 20
    char buf[70];
    snprintf(buf, sizeof(buf), "%s \n",l2s(val,1));
    zemu_log(buf);
    (void) val;
}

#else

void zemu_log_stack_uint64(__Z_UNUSED uint64_t v) {}
void zemu_log_stack_int64(__Z_UNUSED int64_t v) {}


#endif


#if defined(ZEMU_LOGGING) && (defined (TARGET_NANOS) || defined(TARGET_NANOX) || defined(TARGET_NANOS2))
void zemu_trace(const char *file, uint32_t line) {
    char buf[200];
    snprintf(buf, sizeof(buf), "|TRACE| %s:%d\n", file, line);
    zemu_log(buf);
}
#else

void zemu_trace(__Z_UNUSED const char *file, __Z_UNUSED uint32_t line) {}

#endif
