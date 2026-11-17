"""Streaming readers for NVD yearly feeds, shared by the scratch scripts."""
import codecs
import gzip
import json


def text_chunks(path):
    decoder = codecs.getincrementaldecoder("utf-8")()
    with gzip.open(path, "rb") as handle:
        while True:
            raw = handle.read(1 << 22)
            if not raw:
                tail = decoder.decode(b"", final=True)
                if tail:
                    yield tail
                return
            yield decoder.decode(raw)


def array_items(chunks, key='"vulnerabilities"'):
    decoder = json.JSONDecoder()
    buffer, index = "", 0
    for chunk in chunks:
        buffer += chunk
        position = buffer.find(key)
        if position != -1:
            start = buffer.find("[", position)
            if start != -1:
                buffer = buffer[start + 1:]
                break
    else:
        return
    exhausted = False
    while True:
        while index < len(buffer) and buffer[index] in " \r\n\t,":
            index += 1
        if index < len(buffer) and buffer[index] == "]":
            return
        try:
            if index >= len(buffer):
                raise ValueError("need more")
            item, end = decoder.raw_decode(buffer, index)
        except ValueError:
            if exhausted:
                return
            more = next(chunks, None)
            if more is None:
                exhausted = True
                continue
            buffer = buffer[index:] + more
            index = 0
            continue
        yield item
        index = end
        if index > (1 << 22):
            buffer = buffer[index:]
            index = 0
