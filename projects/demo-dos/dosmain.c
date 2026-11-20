/* Demo Quest DOS start-up: the entry point a 32-bit DOS/4GW program needs (Watcom's C runtime calls main), and a
 * switch dense enough for a jump table, the shape a DOS game's state machines have. Written for decompdecomp (CC0). */
#include "game.h"

s32 state_score(s32 state) {
    switch (state) {
    case 0: return 10;
    case 1: return 25;
    case 2: return 50;
    case 3: return 75;
    case 4: return 100;
    case 5: return 150;
    default: return 0;
    }
}

int main(void) {
    s32 i;
    for (i = 0; i < 4; i++) {
        game_tick();
        add_score(state_score(i));
    }
    return 0;
}
