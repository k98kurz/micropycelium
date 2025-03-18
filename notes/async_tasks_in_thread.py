import asyncio
import _thread
from collections import deque
from time import sleep

stop = deque([], 1)
output = deque([], 10)

async def loop(msg, delay):
    while not len(stop):
        output.append(msg)
        await asyncio.sleep(delay)

async def doit(n: int):
    # CPython requires creating an event loop in new threads
    try:
        asyncio.get_running_loop()
    except:
        if hasattr(asyncio, 'set_event_loop'):
            asyncio.set_event_loop(
                asyncio.new_event_loop()
            )
    tasks = []
    for i in range(n):
        tasks.append(loop(str(i), 1.0 + 0.1*i))
    await asyncio.gather(*tasks)

def dooo(n: int):
    # CPython cannot just run(gather(*tasks)), for some reason
    asyncio.run(doit(n))

def cancel():
    sleep(1)
    if len(output):
        print(f'output received')
        print([output.popleft() for _ in range(len(output))])
    stop.append(1)

_thread.start_new_thread(dooo, (5,))
cancel()
