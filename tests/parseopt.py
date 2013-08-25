#!/usr/bin/env python

import sys, os
import string
import subprocess
import json

html_template = string.Template("""
<html>
  <head>
    <title>BPF compiler optimization phases for $expr </title>
    <style type="text/css">
      .hc {
         /* half width container */
         display: inline-block;
         float: left;
         width: 50%;
      }
    </style>

    <script type="text/javascript" src="http://ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js"/></script>
    <script type="text/javascript">
      var expr = '$expr';
      var exprid = $exprid;
      var gcount = $gcount;
      var logs = JSON.parse('$logs');
      logs[gcount] = "";

      var leftsvg = null;
      var rightsvg = null;

      function gurl(index) {
         index += 1;
         if (index < 10)
           s = "00" + index;
         else if (index < 100) 
           s = "0" + index;
         else 
           s = "" + index;
         return "./expr" + exprid + "_g" + s + ".svg"
      }

      function annotate_svgs() {
         if (!leftsvg || !rightsvg) return;

         $$.each([$$(leftsvg), $$(rightsvg)], function() {
           $$(this).find("[id|='block'][opacity]").each(function() {
             $$(this).removeAttr('opacity');
            });
          });
         
         $$(leftsvg).find("[id|='block']").each(function() {
           var has = $$(rightsvg).find("#" + this.id).length != 0;
           if (!has) $$(this).attr("opacity", "0.4");
           else {
             $$(this).click(function() {
                var target = $$(rightsvg).find("#" + this.id);
                var offset = $$("#rightsvgc").offset().top + target.position().top;
                window.scrollTo(0, offset);
                target.focus();
             });
           }
          });
         $$(rightsvg).find("[id|='block']").each(function() {
           var has = $$(leftsvg).find("#" + this.id).length != 0;
           if (!has) $$(this).attr("opacity", "0.4");
           else {
             $$(this).click(function() {
                var target = $$(leftsvg).find("#" + this.id);
                var offset = $$("#leftsvgc").offset().top + target.position().top;
                window.scrollTo(0, offset);
                target.focus();
             });
           }
          });  
      }

      function init_svgroot(svg) {
         svg.setAttribute("width", "100%");
         svg.setAttribute("height", "100%");
      }
      function wait_leftsvg() {
         if (leftsvg) return;
         var doc = document.getElementById("leftsvgc").getSVGDocument();
         if (doc == null) {
            setTimeout(wait_leftsvg, 500);
            return;
         }
         leftsvg = doc.documentElement;
         //console.log(leftsvg);
         // initialize it
         init_svgroot(leftsvg);
         annotate_svgs();
      }
      function wait_rightsvg() {
         if (rightsvg) return;
         var doc = document.getElementById("rightsvgc").getSVGDocument();
         if (doc == null) {
            setTimeout(wait_rightsvg, 500);
            return;
         }
         rightsvg = doc.documentElement;
         //console.log(rightsvg);
         // initialize it
         init_svgroot(rightsvg);
         annotate_svgs();
      }
      function load_left(index) {
        var url = gurl(index);
        var frag = "<embed id='leftsvgc'  type='image/svg+xml' pluginspage='http://www.adobe.com/svg/viewer/install/' src='" + url + "'/>";
        $$("#lsvg").html(frag);
        $$("#lcomment").html(logs[index]);
        $$("#lsvglink").attr("href", url);
        leftsvg = null;
        wait_leftsvg();
      }
      function load_right(index) {
        var url = gurl(index);
        var frag = "<embed id='rightsvgc' type='image/svg+xml' pluginspage='http://www.adobe.com/svg/viewer/install/' src='" + url + "'/>";
        $$("#rsvg").html(frag);
        $$("#rcomment").html(logs[index]);
        $$("#rsvglink").attr("href", url);
        rightsvg = null;
        wait_rightsvg();
      }

      $$(document).ready(function() {
        for (var i = 0; i < gcount; i++) {
          var opt = "<option value='" + i + "'>loop" + i + " -- " + logs[i] + "</option>"; 
          $$("#lselect").append(opt);
          $$("#rselect").append(opt);
        }
        var on_selected = function() {
          var index = parseInt($$(this).children("option:selected").val());
          if (this.id == "lselect")
             load_left(index);
          else 
             load_right(index);
        }
        $$("#lselect").change(on_selected);
        $$("#rselect").change(on_selected);

        $$("#backward").click(function() {
          var index = parseInt($$("#lselect option:selected").val());
          if (index <= 0) return;
          $$("#lselect").val(index - 1).change();
          $$("#rselect").val(index).change();
        });        
        $$("#forward").click(function() {
          var index = parseInt($$("#lselect option:selected").val());
          if (index >= gcount - 2) return;
          $$("#lselect").val(index + 1).change();
          $$("#rselect").val(index + 2).change();
        });

        if (gcount >= 1) $$("#lselect").val(0).change();
        if (gcount >= 2) $$("#rselect").val(1).change();
      });
    </script>
  </head>
  <body style="width: 96%">
    <div>
      <h1>$expr</h1>
      <div style="text-align: center;">
        <button id="backward" type="button">&lt;&lt;</button>
          &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        <button id="forward" type="button">&gt;&gt;</button>
      </div>
    </div>
    <br/>
    <div style="clear: both;">
       <div class="hc lc">
        <select id="lselect"></select>
        <a id="lsvglink" target="_blank">open this svg in browser</a>
        <p id="lcomment"></p>
       </div>
       <div class="hc rc">
        <select id="rselect"></select>
        <a id="rsvglink" target="_blank">open this svg in browser</a>
        <p id="rcomment"></p>
       </div>
    </div>
    <br/>
    <div style="clear: both;">
       <div id="lsvg"  class="hc lc"></div>
       <div id="rsvg" class="hc rc"></div>
    </div>
  </body>
</html>
""")
expr_id = 1

def write_html(expid, expr, gcount, logs):
    logs = map(lambda s: s.strip().replace("\n", "<br/>"), logs)
    
    global html_template
    html = html_template.safe_substitute(exprid=expid, expr=expr, gcount=gcount, logs=json.dumps(logs).encode("string-escape"))
    with file("expr%d.html" % (expid), "wt") as f:
        f.write(html)

def consume_one(expid, expr, finput):
    gid = 1
    log = ""
    dot = ""
    indot = 0
    logs = []
    for line in finput:
        if line.startswith("========"):
            break
        elif line.startswith("digraph BPF {"):
            indot = 1
            dot = line
        elif indot:
            dot += line
            if line.startswith("}"):
                indot = 2
        else:
            log += line
            
        if indot == 2:
            p = subprocess.Popen(['dot', '-Tsvg'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            svg = p.communicate(dot)[0]
            with file("expr%d_g%03d.svg" % (expid, gid), "wt") as f:
                f.write(svg)

            logs.append(log)
            gid += 1
            log = ""
            dot = ""
            indot = 0
            
    if indot != 0:
        print >>sys.stderr, "unterminated dot graph for expression", expr
    
    write_html(expid, expr, gid - 1, logs)

def run_httpd():
    import SimpleHTTPServer
    import SocketServer
    PORT = 8888
    
    class MySocketServer(SocketServer.TCPServer):
        allow_reuse_address = True
    Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
    httpd = MySocketServer(("", PORT), Handler)
    print "html pages generated, access them by following url:"
    for i in range(1, expr_id):
        print "  http://localhost:%d/expr%d.html" % (PORT, i)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt as e:
        sys.exit(0)

def main():
    global expr_id
    finput = sys.stdin
    for line in finput:
        if line.startswith("compile BPF expression: "):
            bpfexpr = line[len("compile BPF expression: "):].strip()
            consume_one(expr_id, bpfexpr, finput)
            expr_id += 1
    if expr_id > 1:
        run_httpd()
    
if __name__ == "__main__":
    main()
