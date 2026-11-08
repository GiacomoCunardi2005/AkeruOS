"""Offline luminance reference for explicitly calibrated synthetic CFA samples."""

WEIGHTS = (0.2126, 0.7152, 0.0722)


def luminance(samples, pattern, black, white, matrix):
    """Bilinear CFA reconstruction and sensor-RGB to linear-sRGB luminance.

    `pattern` is a 2x2 Bayer tile, `black`/`white` are per-channel levels,
    and `matrix` converts normalized sensor RGB to linear sRGB. The return is
    an unclipped floating-point image; all calibration is supplied by the caller.
    """
    height = len(samples)
    width = len(samples[0]) if height else 0
    if height < 2 or width < 2 or any(len(row) != width for row in samples):
        raise ValueError('samples must be rectangular and at least 2x2')
    if len(pattern) != 2 or any(len(row) != 2 for row in pattern):
        raise ValueError('pattern must be a 2x2 Bayer tile')
    tile = [c for row in pattern for c in row]
    if sorted(tile) != ['B', 'G', 'G', 'R'] or ((pattern[0][0] == 'G') != (pattern[1][1] == 'G')):
        raise ValueError('invalid Bayer tile')
    if any(c not in black or c not in white or white[c] <= black[c] for c in 'RGB'):
        raise ValueError('each channel needs white greater than black')
    if len(matrix) != 3 or any(len(row) != 3 for row in matrix):
        raise ValueError('matrix must be 3x3')

    def color(y, x):
        return pattern[y % 2][x % 2]

    def channel(y, x, wanted):
        if color(y, x) == wanted:
            locations = [(y, x)]
        else:
            locations = [(yy, xx) for yy in range(max(0, y - 1), min(height, y + 2))
                         for xx in range(max(0, x - 1), min(width, x + 2))
                         if color(yy, xx) == wanted]
        return sum((samples[yy][xx] - black[wanted]) / (white[wanted] - black[wanted])
                   for yy, xx in locations) / len(locations)

    result = []
    for y in range(height):
        row = []
        for x in range(width):
            rgb = [channel(y, x, c) for c in 'RGB']
            linear = [sum(matrix[i][j] * rgb[j] for j in range(3)) for i in range(3)]
            row.append(sum(WEIGHTS[i] * linear[i] for i in range(3)))
        result.append(row)
    return result
