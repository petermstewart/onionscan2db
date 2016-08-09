# onionscan2db
> Parses multiple JSON formatted OnionScan results into an SQLite database.

Python 2.7 utility which parses multiple JSON formatted results files from [OnionScan](https://github.com/s-rah/onionscan) (and, by extension, [OnionRunner](https://github.com/automatingosint/osint_public/tree/master/onionrunner)) into an SQLite database for further analysis.

Minimal error handling. Database inserts could almost certainly be more efficient. You get what you pay for.

[Blog post](https://www.petermstewart.net/onionscan2db)

## Usage

```sh
python onionscan2db -d <directory> -o <output-file>
```

## Thanks

[Sarah Jamie Lewis](https://twitter.com/sarahjamielewis) for OnionScan, and [Justin Seitz](https://twitter.com/jms_dot_py) for the [automation layer](http://www.automatingosint.com/blog/2016/07/dark-web-osint-with-python-and-onionscan-part-one/).

## License

#### MIT License


Copyright (c) 2016 Peter Stewart

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
