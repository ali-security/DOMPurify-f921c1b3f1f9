(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined'
    ? (module.exports = factory())
    : typeof define === 'function' && define.amd
    ? define(factory)
    : ((global =
        typeof globalThis !== 'undefined' ? globalThis : global || self),
      (global.testSuite = factory()));
})(this, function () {
  return function testSuite(
    DOMPurify,
    window,
    sanitizationTestCases,
    xssTestCases
  ) {
    var document = window.document;
    var jQuery = window.jQuery;

    sanitizationTestCases.forEach((testCase) => {
      QUnit.test(`Sanitization test[${testCase.title}]`, (assert) => {
        assert.contains(
          DOMPurify.sanitize(testCase.payload),
          testCase.expected,
          `Payload: ${testCase.payload}`
        );
      });
    });

    // XSS tests: Native DOM methods (alert() should not be called)
    xssTestCases.forEach((testCase) => {
      QUnit.test(`XSS test: native[${testCase.title}]`, (assert) => {
        document.getElementById('qunit-fixture').innerHTML = DOMPurify.sanitize(
          testCase.payload
        );
        const done = assert.async();
        setTimeout(() => {
          assert.notEqual(window.xssed, true, 'alert() was called');
          // Teardown
          document.getElementById('qunit-fixture').innerHTML = '';
          window.xssed = false;
          done();
        }, 100);
      });
    });
    // XSS tests: jQuery (alert() should not be called)
    xssTestCases.forEach((testCase) => {
      QUnit.test(`XSS test: jQuery[${testCase.title}]`, (assert) => {
        jQuery('#qunit-fixture').html(DOMPurify.sanitize(testCase.payload));
        const done = assert.async();
        setTimeout(() => {
          assert.notEqual(window.xssed, true, 'alert() was called');
          // Teardown
          jQuery('#qunit-fixture').empty();
          window.xssed = false;
          done();
        }, 100);
      });
    });
    // document.write tests to handle FF's strange behavior
    xssTestCases.forEach((testCase) => {
      QUnit.test(
        `XSS test: document.write() into iframe[${testCase.title}]`,
        (assert) => {
          const done = assert.async();
          const iframe = document.createElement('iframe');
          iframe.src = 'about:blank';
          iframe.onload = function () {
            iframe.contentDocument.write(
              '<script>window.alert=function(){top.xssed=true;}</script>' +
                DOMPurify.sanitize(testCase.payload)
            );
            assert.notEqual(
              window.xssed,
              true,
              'alert() was called from document.write()'
            );
            window.xssed = false;
            iframe.parentNode.removeChild(iframe);
            done();
          };
          document.body.appendChild(iframe);
        }
      );
    });

    // Config-Flag Tests
    QUnit.test(
      'Config-Flag tests: KEEP_CONTENT + ALLOWED_TAGS / ALLOWED_ATTR',
      function (assert) {
        // KEEP_CONTENT + ALLOWED_TAGS / ALLOWED_ATTR
        assert.equal(
          DOMPurify.sanitize('<iframe>Hello</iframe>', { KEEP_CONTENT: false }),
          ''
        );
        assert.contains(
          DOMPurify.sanitize(
            '<a href="#">abc<b style="color:red">123</b><q class="cite">123</b></a>',
            {
              ALLOWED_TAGS: ['b', 'q'],
              ALLOWED_ATTR: ['style'],
              KEEP_CONTENT: true,
            }
          ),
          [
            'abc<b style="color:red">123</b><q>123</q>',
            'abc<b style="color: red;">123</b><q>123</q>',
          ]
        );
        assert.equal(
          DOMPurify.sanitize(
            '<a href="#">abc<b style="color:red">123</b><q class="cite">123</b></a>',
            {
              ALLOWED_TAGS: ['b', 'q'],
              ALLOWED_ATTR: ['style'],
              KEEP_CONTENT: false,
            }
          ),
          ''
        );
        assert.equal(
          DOMPurify.sanitize('<a href="#">abc</a>', {
            ALLOWED_TAGS: ['b', 'q'],
            KEEP_CONTENT: false,
          }),
          ''
        );
        assert.equal(
          DOMPurify.sanitize('<form><input name="parentNode"></form>', {
            ALLOWED_TAGS: ['input'],
            KEEP_CONTENT: true,
          }),
          '<input>'
        );
      }
    );
    QUnit.test('Config-Flag tests: ALLOW_SELF_CLOSE_IN_ATTR', function (assert) {
      // ALLOW_SELF_CLOSE_IN_ATTR
      assert.contains(
        DOMPurify.sanitize('<a href="#" class="foo <br/>">abc</a>', {
          ALLOW_SELF_CLOSE_IN_ATTR: false,
        }),
        ['<a href="#">abc</a>',	"<a class=\"foo &lt;br/&gt;\" href=\"#\">abc</a>"]

      );
      assert.contains(
        DOMPurify.sanitize('<a href="#" class="foo <br/>">abc</a>', {
          ALLOW_SELF_CLOSE_IN_ATTR: true,
        }),
        ['<a class="foo <br/>" href="#">abc</a>', "<a class=\"foo &lt;br/&gt;\" href=\"#\">abc</a>"]
      );
    });
    QUnit.test('Config-Flag tests: ALLOW_DATA_ATTR', function (assert) {
      // ALLOW_DATA_ATTR
      assert.equal(
        DOMPurify.sanitize('<a href="#" data-abc"="foo">abc</a>', {
          ALLOW_DATA_ATTR: true,
        }),
        '<a href="#">abc</a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" data-abc="foo">abc</a>', {
          ALLOW_DATA_ATTR: false,
        }),
        '<a href="#">abc</a>'
      );
      assert.contains(
        DOMPurify.sanitize('<a href="#" data-abc="foo">abc</a>', {
          ALLOW_DATA_ATTR: true,
        }),
        [
          '<a data-abc="foo" href="#">abc</a>',
          '<a href="#" data-abc="foo">abc</a>',
        ]
      );
      assert.contains(
        DOMPurify.sanitize('<a href="#" data-abc-1-2-3="foo">abc</a>', {
          ALLOW_DATA_ATTR: true,
        }),
        [
          '<a data-abc-1-2-3="foo" href="#">abc</a>',
          '<a href="#" data-abc-1-2-3="foo">abc</a>',
        ]
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" data-""="foo">abc</a>', {
          ALLOW_DATA_ATTR: true,
        }),
        '<a href="#">abc</a>'
      );
      assert.contains(
        DOMPurify.sanitize('<a href="#" data-äöü="foo">abc</a>', {
          ALLOW_DATA_ATTR: true,
        }),
        [
          '<a href="#" data-äöü="foo">abc</a>',
          '<a data-äöü="foo" href="#">abc</a>',
        ]
      );
      assert.contains(
        DOMPurify.sanitize('<a href="#" data-\u00B7._="foo">abc</a>', {
          ALLOW_DATA_ATTR: true,
        }),
        [
          '<a data-\u00B7._="foo" href="#">abc</a>',
          '<a href="#">abc</a>',
          '<a href="#" data-·._="foo">abc</a>',
        ] // IE11 and Edge throw an InvalidCharacterError
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" data-\u00B5="foo">abc</a>', {
          ALLOW_DATA_ATTR: true,
        }),
        '<a href="#">abc</a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" data-evil="foo">abc</a>', {
          FORBID_ATTR: ['data-evil'],
        }),
        '<a href="#">abc</a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" data-evil="foo">abc</a>', {
          ALLOW_DATA_ATTR: true,
          FORBID_ATTR: ['data-evil'],
        }),
        '<a href="#">abc</a>'
      );
    });
    QUnit.test('Config-Flag tests: ADD_TAGS', function (assert) {
      // ADD_TAGS
      assert.equal(
        DOMPurify.sanitize('<my-component>abc</my-component>', {
          ADD_TAGS: ['my-component'],
        }),
        '<my-component>abc</my-component>'
      );
    });
    QUnit.test('Config-Flag tests: ADD_TAGS + ADD_ATTR', function (assert) {
      // ADD_TAGS + ADD_ATTR
      assert.equal(
        DOMPurify.sanitize('<my-component my-attr="foo">abc</my-component>', {
          ADD_TAGS: ['my-component'],
        }),
        '<my-component>abc</my-component>'
      );
      assert.equal(
        DOMPurify.sanitize('<my-component my-attr="foo">abc</my-component>', {
          ADD_TAGS: ['my-component'],
          ADD_ATTR: ['my-attr'],
        }),
        '<my-component my-attr="foo">abc</my-component>'
      );
    });
    QUnit.test(
      'Config-Flag tests: FORBID_CONTENTS + FORBID_TAGS',
      function (assert) {
        // FORBID_CONTENTS + FORBID_TAGS
        assert.equal(
          DOMPurify.sanitize(
            '<div><b>preserve me</b></div><p><b>no not preserve me</b></p>',
            { FORBID_CONTENTS: ['p'], FORBID_TAGS: ['div', 'p'] }
          ),
          '<b>preserve me</b>'
        );
      }
    );
    QUnit.test(
      'Config-Flag tests: SAFE_FOR_JQUERY (now inactive, secure by default)',
      function (assert) {
        assert.equal(
          DOMPurify.sanitize(
            '<a>123</a><option><style><img src=x onerror=alert(1)>'
          ),
          '<a>123</a><option></option>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<a>123</a><option><style><img src=x onerror=alert(1)>'
          ),
          '<a>123</a><option></option>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<option><style></option></select><b><img src=xx: onerror=alert(1)></style></option>'
          ),
          '<option></option>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<option><iframe></select><b><script>alert(1)</script>'
          ),
          '<option></option>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<option><iframe></select><b><script>alert(1)</script>'
          ),
          '<option></option>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<b><style><style/><img src=xx: onerror=alert(1)>'
          ),
          '<b></b>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<b><style><style/><img src=xx: onerror=alert(1)>'
          ),
          '<b></b>'
        );
        assert.contains(
          DOMPurify.sanitize('1<template><s>000</s></template>2'),
          ['1<template><s>000</s></template>2', '1<template></template>2', '12']
        );
        assert.contains(DOMPurify.sanitize('<template><s>000</s></template>'), [
          '',
          '<template><s>000</s></template>',
        ]);
        // see https://github.com/cure53/DOMPurify/issues/283
        assert.equal(
          DOMPurify.sanitize('<i>&amp;amp; &lt;</i>'),
          '<i>&amp;amp; &lt;</i>'
        );
      }
    );
    QUnit.test('Config-Flag tests: SAFE_FOR_TEMPLATES', function (assert) {
      //SAFE_FOR_TEMPLATES
      assert.equal(
        DOMPurify.sanitize(
          '<a>123{{456}}<b><style><% alert(1) %></style>456</b></a>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        '<a> <b><style> </style>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a data-bind="style: alert(1)"></a>', {
          SAFE_FOR_TEMPLATES: true,
        }),
        '<a></a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a data-harmless=""></a>', {
          SAFE_FOR_TEMPLATES: true,
          ALLOW_DATA_ATTR: true,
        }),
        '<a></a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a data-harmless=""></a>', {
          SAFE_FOR_TEMPLATES: false,
          ALLOW_DATA_ATTR: false,
        }),
        '<a></a>'
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a>{{123}}{{456}}<b><style><% alert(1) %><% 123 %></style>456</b></a>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        '<a> <b><style> </style>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a>{{123}}abc{{456}}<b><style><% alert(1) %>def<% 123 %></style>456</b></a>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        '<a> <b><style> </style>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a>123{{45{{6}}<b><style><% alert(1)%> %></style>456</b></a>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        '<a> <b><style> </style>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a>123{{45}}6}}<b><style><% <%alert(1) %></style>456</b></a>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        '<a> <b><style> </style>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a>123{{<b>456}}</b><style><% alert(1) %></style>456</a>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        '<a>123 <b> </b><style> </style>456</a>'
      );
      assert.contains(
        DOMPurify.sanitize(
          '<b>{{evil<script>alert(1)</script><form><img src=x name=textContent></form>}}</b>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        ['<b>  </b>', '<b> </b>', '<b> <form><img src="x"></form> </b>']
      );
      assert.contains(
        DOMPurify.sanitize(
          '<b>he{{evil<script>alert(1)</script><form><img src=x name=textContent></form>}}ya</b>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        [
          '<b>he  ya</b>',
          '<b>he </b>',
          '<b>he <form><img src="x"></form> ya</b>',
        ]
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a>123<% <b>456}}</b><style>{{ alert(1) }}</style>456 %></a>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        '<a>123 <b> </b><style> </style> </a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a href="}}javascript:alert(1)"></a>', {
          SAFE_FOR_TEMPLATES: true,
        }),
        '<a></a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a class="{{999-333}}"></a>', {
          SAFE_FOR_TEMPLATES: true,
        }),
        '<a class=" "></a>'
      );
      assert.equal(
        DOMPurify.sanitize('{{999-333}}', { SAFE_FOR_TEMPLATES: true }),
        ' '
      );
      assert.equal(
        DOMPurify.sanitize('{<x>{333+333}<x>}', { SAFE_FOR_TEMPLATES: true }),
        ' '
      );
    });
    QUnit.test(
      'Config-Flag tests: SAFE_FOR_TEMPLATES unterminated template literal',
      function (assert) {
        // An opening `${` must be scrubbed up to the end of the string, even
        // without a closing `}`. Otherwise a `${` left in one node and a `}`
        // in a later attribute value let the final template scrub cut out the
        // markup in between, turning attribute content into live HTML (mXSS)
        var clean = DOMPurify.sanitize(
          '<b>${</b><a title="}<img src=x onerror=alert(1)>"></a>',
          { SAFE_FOR_TEMPLATES: true }
        );
        assert.contains(clean, [
          '<b> </b><a title="}<img src=x onerror=alert(1)>"></a>',
          '<b> </b><a title="}&lt;img src=x onerror=alert(1)&gt;"></a>',
        ]);
        var doc = document.implementation.createHTMLDocument('');
        doc.body.innerHTML = clean;
        assert.equal(doc.body.getElementsByTagName('img').length, 0);
        assert.equal(
          DOMPurify.sanitize('<b>abc${def</b>', { SAFE_FOR_TEMPLATES: true }),
          '<b>abc </b>'
        );
        assert.equal(
          DOMPurify.sanitize('<a title="abc${def"></a>', {
            SAFE_FOR_TEMPLATES: true,
          }),
          '<a title="abc "></a>'
        );
      }
    );
    QUnit.test(
      'Config-Flag tests: SAFE_FOR_TEMPLATES RETURN_DOM CVE-2026-41239',
      function (assert) {
        // RETURN_DOM returns before the final template scrub of the serialized
        // string, so an expression split across adjacent text nodes (by
        // elements or comments that get removed) must not survive in the DOM
        var dom = DOMPurify.sanitize(
          "<div>{<foo></foo>{constructor.constructor('alert(1)')()}<foo></foo>}</div>",
          { SAFE_FOR_TEMPLATES: true, RETURN_DOM: true }
        );
        assert.equal(dom.outerHTML, '<body> </body>');
        dom = DOMPurify.sanitize('<div>{<!---->{7*7}<!---->}</div>', {
          SAFE_FOR_TEMPLATES: true,
          RETURN_DOM: true,
        });
        assert.equal(dom.outerHTML, '<body> </body>');
        dom = DOMPurify.sanitize('<div>$<foo></foo>{alert(1)}</div>', {
          SAFE_FOR_TEMPLATES: true,
          RETURN_DOM: true,
        });
        assert.equal(dom.outerHTML, '<body><div> </div></body>');
        dom = DOMPurify.sanitize('<div>{<foo></foo>{7*7}<foo></foo>}</div>', {
          SAFE_FOR_TEMPLATES: true,
          RETURN_DOM: true,
          WHOLE_DOCUMENT: true,
        });
        assert.equal(dom.innerHTML.indexOf('{{'), -1);
        assert.equal(dom.textContent.indexOf('{{'), -1);
        // a DOM node input whose text is already split across text nodes
        var dirty = document.createElement('div');
        dirty.appendChild(document.createTextNode('{'));
        dirty.appendChild(document.createTextNode('{7*7}'));
        dirty.appendChild(document.createTextNode('}'));
        dom = DOMPurify.sanitize(dirty, {
          SAFE_FOR_TEMPLATES: true,
          RETURN_DOM: true,
        });
        assert.equal(dom.outerHTML, '<body> </body>');
        // content without template expressions is left untouched
        assert.equal(
          DOMPurify.sanitize('<p>abc</p><p>def</p>', {
            SAFE_FOR_TEMPLATES: true,
            RETURN_DOM: true,
          }).outerHTML,
          '<body><p>abc</p><p>def</p></body>'
        );
      }
    );
    QUnit.test(
      'Config-Flag tests: SAFE_FOR_TEMPLATES RETURN_DOM_FRAGMENT CVE-2026-41239',
      function (assert) {
        var fragment = DOMPurify.sanitize(
          "<div>{<foo></foo>{constructor.constructor('alert(1)')()}<foo></foo>}</div>",
          { SAFE_FOR_TEMPLATES: true, RETURN_DOM_FRAGMENT: true }
        );
        assert.equal(fragment.nodeType, 11);
        var holder = document.createElement('div');
        holder.appendChild(fragment);
        assert.equal(holder.innerHTML, ' ');
        assert.equal(holder.textContent.indexOf('{{'), -1);
        fragment = DOMPurify.sanitize('<div>$<foo></foo>{alert(1)}</div>', {
          SAFE_FOR_TEMPLATES: true,
          RETURN_DOM_FRAGMENT: true,
        });
        holder = document.createElement('div');
        holder.appendChild(fragment);
        assert.equal(holder.innerHTML, '<div> </div>');
      }
    );
    QUnit.test('Config-Flag tests: SANITIZE_DOM', function (assert) {
      // SANITIZE_DOM
      assert.equal(
        DOMPurify.sanitize('<img src="x" name="implementation">', {
          SANITIZE_DOM: true,
        }),
        '<img src="x">'
      );
      assert.equal(
        DOMPurify.sanitize('<img src="x" name="createNodeIterator">', {
          SANITIZE_DOM: true,
        }),
        '<img src="x">'
      );
      assert.equal(
        DOMPurify.sanitize('<img src="x" name="getElementById">', {
          SANITIZE_DOM: false,
        }),
        '<img name="getElementById" src="x">'
      );
      assert.equal(
        DOMPurify.sanitize('<img src="x" name="getElementById">', {
          SANITIZE_DOM: true,
        }),
        '<img src="x">'
      );
      assert.equal(
        DOMPurify.sanitize('<a href="x" id="location">click</a>', {
          SANITIZE_DOM: true,
        }),
        '<a href="x">click</a>'
      );
      assert.contains(
        DOMPurify.sanitize('<form><input name="attributes"></form>', {
          ADD_TAGS: ['form'],
          SANITIZE_DOM: false,
        }),
        ['', '<form><input name="attributes"></form>']
      );
      assert.contains(
        DOMPurify.sanitize('<form><input name="attributes"></form>', {
          ADD_TAGS: ['form'],
          SANITIZE_DOM: true,
        }),
        ['', '<form><input name="attributes"></form>', '<form><input></form>']
      );
    });
    QUnit.test('Config-Flag tests: SANITIZE_NAMED_PROPS', function (assert) {
      // SANITIZE_NAMED_PROPS
      assert.equal(
        DOMPurify.sanitize('<a id="x"></a>', {
          SANITIZE_NAMED_PROPS: true,
        }),
        '<a id="user-content-x"></a>'
      );
      assert.equal(
        DOMPurify.sanitize('<form id="x"><input id="y"></form>', {
          SANITIZE_NAMED_PROPS: true,
        }),
        '<form id="user-content-x"><input id="user-content-y"></form>'
      );
      assert.equal(
        DOMPurify.sanitize('<a id="x"></a><a id="x"></a>', {
          SANITIZE_NAMED_PROPS: true,
        }),
        '<a id="user-content-x"></a><a id="user-content-x"></a>'
      );
    });
    QUnit.test('Config-Flag tests: WHOLE_DOCUMENT', function (assert) {
      //WHOLE_DOCUMENT
      assert.equal(DOMPurify.sanitize('123', { WHOLE_DOCUMENT: false }), '123');
      assert.equal(
        DOMPurify.sanitize('123', { WHOLE_DOCUMENT: true }),
        '<html><head></head><body>123</body></html>'
      );
      assert.equal(
        DOMPurify.sanitize('<style>*{color:red}</style>', {
          WHOLE_DOCUMENT: false,
        }),
        ''
      );
      assert.equal(
        DOMPurify.sanitize('<style>*{color:red}</style>', {
          WHOLE_DOCUMENT: true,
        }),
        '<html><head><style>*{color:red}</style></head><body></body></html>'
      );
      assert.equal(
        DOMPurify.sanitize('123<style>*{color:red}</style>', {
          WHOLE_DOCUMENT: false,
        }),
        '123<style>*{color:red}</style>'
      );
      assert.equal(
        DOMPurify.sanitize('123<style>*{color:red}</style>', {
          WHOLE_DOCUMENT: true,
        }),
        '<html><head></head><body>123<style>*{color:red}</style></body></html>'
      );
      assert.equal(
        DOMPurify.sanitize('<!DOCTYPE html><html><body>123</body></html>', {
          WHOLE_DOCUMENT: true,
        }),
        '<html><head></head><body>123</body></html>'
      );
      assert.equal(
        DOMPurify.sanitize('<!DOCTYPE html><html><body>123</body></html>', {
          WHOLE_DOCUMENT: true,
          ADD_TAGS: ['!doctype'],
        }),
        '<!DOCTYPE html>\n<html><head></head><body>123</body></html>'
      );
    });
    QUnit.test('Config-Flag tests: RETURN_DOM', function (assert) {
      //RETURN_DOM
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456</b></a>', { RETURN_DOM: true })
          .outerHTML,
        '<body><a>123<b>456</b></a></body>'
      );
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456<script>alert(1)</script></b></a>', {
          RETURN_DOM: true,
        }).outerHTML,
        '<body><a>123<b>456</b></a></body>'
      );
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456</b></a>', {
          RETURN_DOM: true,
          WHOLE_DOCUMENT: true,
        }).outerHTML,
        '<html><head></head><body><a>123<b>456</b></a></body></html>'
      );
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456<script>alert(1)</script></b></a>', {
          RETURN_DOM: true,
          WHOLE_DOCUMENT: true,
        }).outerHTML,
        '<html><head></head><body><a>123<b>456</b></a></body></html>'
      );
      assert.equal(
        DOMPurify.sanitize('123', { RETURN_DOM: true }).outerHTML,
        '<body>123</body>'
      );
    });
    QUnit.test('Config-Flag tests: shadowroot', function (assert) {
      assert.notEqual(
        DOMPurify.sanitize('123', {
          RETURN_DOM: true,
        }).ownerDocument,
        document
      );
      assert.equal(
        DOMPurify.sanitize('123', {
          RETURN_DOM: true,
          ADD_ATTR: ['shadowroot'],
        }).ownerDocument,
        document
      );
      assert.notEqual(
        DOMPurify.sanitize('123', {
          RETURN_DOM_FRAGMENT: true,
        }).ownerDocument,
        document
      );
      assert.equal(
        DOMPurify.sanitize('123', {
          RETURN_DOM_FRAGMENT: true,
          ADD_ATTR: ['shadowroot'],
        }).ownerDocument,
        document
      );
    });
    QUnit.test('Config-Flag tests: RETURN_DOM_FRAGMENT', function (assert) {
      //RETURN_DOM_FRAGMENT
      // attempt clobbering
      var fragment = DOMPurify.sanitize(
        'foo<img id="createDocumentFragment">',
        {
          RETURN_DOM_FRAGMENT: true,
        }
      );
      assert.equal(fragment.nodeType, 11);
      assert.notEqual(fragment.ownerDocument, document);
      assert.equal(fragment.firstChild && fragment.firstChild.nodeValue, 'foo');
      // again, but without SANITIZE_DOM
      fragment = DOMPurify.sanitize('foo<img id="createDocumentFragment">', {
        RETURN_DOM_FRAGMENT: true,
        SANITIZE_DOM: false,
      });
      assert.equal(fragment.nodeType, 11);
      assert.notEqual(fragment.ownerDocument, document);
      assert.equal(fragment.firstChild && fragment.firstChild.nodeValue, 'foo');
    });
    QUnit.test('Config-Flag tests: RETURN_DOM_FRAGMENT', function (assert) {
      var xss = `<body><div><template shadowroot=open><img src=x onerror=alert(3)></template></div></body>`;
      var dom_body = DOMPurify.sanitize(xss, { RETURN_DOM: true });
      assert.equal(
        dom_body.outerHTML,
        '<body><div><template><img src="x"></template></div></body>'
      );
    });
    QUnit.test('Config-Flag tests: IN_PLACE', function (assert) {
      //IN_PLACE
      var dirty = document.createElement('a');
      dirty.setAttribute('href', 'javascript:alert(1)');
      var clean = DOMPurify.sanitize(dirty, { IN_PLACE: true });
      assert.equal(dirty, clean); // should return the input node
      assert.equal(dirty.href, ''); // should still sanitize
    });
    QUnit.test(
      'Config-Flag tests: IN_PLACE insecure root-nodes',
      function (assert) {
        //IN_PLACE with insecure root node (script)
        var dirty = document.createElement('script');
        dirty.setAttribute('src', 'data:,alert(1)');
        assert.throws(function () {
          DOMPurify.sanitize(dirty, { IN_PLACE: true });
        });
      }
    );
    QUnit.test(
      'Config-Flag tests: IN_PLACE insecure root-nodes',
      function (assert) {
        //IN_PLACE with insecure root node (iframe)
        var dirty = document.createElement('iframe');
        dirty.setAttribute('src', 'javascript:alert(1)');
        assert.throws(function () {
          DOMPurify.sanitize(dirty, { IN_PLACE: true });
        });
      }
    );
    QUnit.test(
      'Config-Flag tests: IN_PLACE throws instead of returning a force-removed rawtext root (mXSS reparse) CVE-2026-109345',
      function (assert) {
        // A <style> passed as the IN_PLACE root whose text content already
        // carries its own end tag is force-removed by the mXSS text probe:
        // its literal serialization ("</style><img ...>") re-opens markup on
        // an HTML reparse. Attribute sanitization cancels the attribute axis
        // (the onclick below) but cannot defang rawtext text, so the removed
        // root must not be handed back to the caller. Fail closed - assert
        // the return contract, not merely a scrubbed textContent.
        var dirty = document.createElement('style');
        dirty.setAttribute('onclick', 'alert(1)');
        dirty.textContent = '</style><img src=x onerror=alert(1)>';
        document.body.appendChild(dirty);

        try {
          assert.throws(
            function () {
              DOMPurify.sanitize(dirty, { IN_PLACE: true });
            },
            /refusing to sanitize in place/,
            'force-removed rawtext root is not returned'
          );

          var recorded = false;
          for (var i = 0; i < DOMPurify.removed.length; i++) {
            if (DOMPurify.removed[i].element === dirty) {
              recorded = true;
            }
          }

          assert.ok(
            recorded,
            'root was recorded as removed during the aborted call'
          );
        } finally {
          if (dirty.parentNode) {
            dirty.parentNode.removeChild(dirty);
          }

          window.xssed = false;
        }
      }
    );
    QUnit.test(
      'Config-Flag tests: IN_PLACE throws for a parent-less force-removed rawtext root CVE-2026-109345',
      function (assert) {
        // A parent-less root cannot be detached by _forceRemove at all, so
        // without the fail-closed check the very same node - text payload
        // intact - came back to the caller, and storing / re-rendering its
        // outerHTML produced a live <img onerror>. No src on the payload, so
        // the probe below cannot actually fire it.
        var dirty = document.createElement('style');
        dirty.textContent = '</style><img onerror=alert(1)>';

        var returned = null;
        assert.throws(
          function () {
            returned = DOMPurify.sanitize(dirty, { IN_PLACE: true });
          },
          /refusing to sanitize in place/,
          'parent-less force-removed rawtext root is not returned'
        );

        var probe = document.createElement('div');
        probe.innerHTML = returned ? returned.outerHTML : '';
        assert.notOk(
          probe.querySelector('[onerror],[onload],script'),
          'no executable sink is handed back for re-rendering: ' +
            probe.innerHTML
        );
      }
    );
    QUnit.test(
      'Config-Flag tests: IN_PLACE throws for a root force-removed by the select/template check CVE-2026-109345',
      function (assert) {
        // The check is not tied to the rawtext probe: any root-kill reason
        // (here the <select> + <template> mitigation) must fail closed
        // rather than return the removed root.
        var dirty = document.createElement('select');
        dirty.appendChild(document.createElement('template'));
        document.body.appendChild(dirty);

        try {
          assert.throws(
            function () {
              DOMPurify.sanitize(dirty, { IN_PLACE: true });
            },
            /refusing to sanitize in place/,
            'force-removed select root is not returned'
          );
        } finally {
          if (dirty.parentNode) {
            dirty.parentNode.removeChild(dirty);
          }
        }
      }
    );
    QUnit.test(
      'Config-Flag tests: IN_PLACE still returns the root when a rawtext CHILD (not the root) is removed CVE-2026-109345',
      function (assert) {
        // The fail-closed guard must fire ONLY when the ROOT itself is
        // force-removed. A dangerous rawtext child is detached from the
        // returned root as usual; the root remains safe to return, so the
        // guard must not over-trigger on ordinary child removals.
        var dirty = document.createElement('div');
        dirty.innerHTML = '<span>ok</span>';
        var style = document.createElement('style');
        style.textContent = '</style><img src=x onerror=alert(1)>';
        dirty.appendChild(style);
        document.body.appendChild(dirty);

        try {
          var clean = DOMPurify.sanitize(dirty, { IN_PLACE: true });
          assert.equal(clean, dirty, 'returns the input root');
          assert.equal(
            dirty.querySelector('style'),
            null,
            'dangerous rawtext child removed from the returned root'
          );
          assert.equal(
            dirty.querySelector('span').textContent,
            'ok',
            'safe sibling content preserved'
          );
        } finally {
          if (dirty.parentNode) {
            dirty.parentNode.removeChild(dirty);
          }

          window.xssed = false;
        }
      }
    );
    QUnit.test('Config-Flag tests: FORBID_TAGS', function (assert) {
      //FORBID_TAGS
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456</b></a>', { FORBID_TAGS: ['b'] }),
        '<a>123456</a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456<script>alert(1)</script></b></a>789', {
          FORBID_TAGS: ['a', 'b'],
        }),
        '123456789'
      );
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456</b></a>', { FORBID_TAGS: ['c'] }),
        '<a>123<b>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456<script>alert(1)</script></b></a>789', {
          FORBID_TAGS: ['script', 'b'],
        }),
        '<a>123456</a>789'
      );
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456</b></a>', {
          ADD_TAGS: ['b'],
          FORBID_TAGS: ['b'],
        }),
        '<a>123456</a>'
      );
    });
    QUnit.test('Config-Flag tests: FORBID_ATTR', function (assert) {
      //FORBID_ATTR
      assert.equal(
        DOMPurify.sanitize('<a x="1">123<b>456</b></a>', {
          FORBID_ATTR: ['x'],
        }),
        '<a>123<b>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a class="0" x="1">123<b y="1">456<script>alert(1)</script></b></a>789',
          { FORBID_ATTR: ['x', 'y'] }
        ),
        '<a class="0">123<b>456</b></a>789'
      );
      assert.equal(
        DOMPurify.sanitize('<a y="1">123<b y="1" y="2">456</b></a>', {
          FORBID_ATTR: ['y'],
        }),
        '<a>123<b>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a>123<b x="1">456<script y="1">alert(1)</script></b></a>789',
          { FORBID_ATTR: ['x', 'y'] }
        ),
        '<a>123<b>456</b></a>789'
      );
    });
    QUnit.test(
      'Config-Param tests: CUSTOM_ELEMENT_HANDLING',
      function (assert) {
        //CUSTOM_ELEMENT_HANDLING
        assert.equal(
          DOMPurify.sanitize(
            '<foo-bar baz="foobar" forbidden="true"></foo-bar><div is="foo-baz"></div>',
            {
              CUSTOM_ELEMENT_HANDLING: {
                tagNameCheck: /^foo-/,
                attributeNameCheck: /baz/,
                allowCustomizedBuiltInElements: true,
              },
            }
          ),
          '<foo-bar baz="foobar"></foo-bar><div is="foo-baz"></div>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<foo-bar baz="foobar" forbidden="true"></foo-bar><div is="foo-baz"></div>',
            {
              CUSTOM_ELEMENT_HANDLING: {
                tagNameCheck: /^foo-/,
                attributeNameCheck: /baz/,
                allowCustomizedBuiltInElements: false,
              },
            }
          ),
          '<foo-bar baz="foobar"></foo-bar><div is=""></div>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<foo-bar baz="foobar" forbidden="true"></foo-bar><div is="foo-baz"></div>',
            {
              CUSTOM_ELEMENT_HANDLING: {
                tagNameCheck: /-bar$/,
                attributeNameCheck: /.+/,
                allowCustomizedBuiltInElements: true,
              },
            }
          ), // DOMPurify swaps the order of attributes here!
          '<foo-bar forbidden="true" baz="foobar"></foo-bar><div is=""></div>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<foo-bar baz="foobar" forbidden="true"></foo-bar><div is="foo-baz"></div>',
            {
              CUSTOM_ELEMENT_HANDLING: {
                tagNameCheck: (tagName) => tagName.match(/^foo-/),
                attributeNameCheck: (attr) => attr.match(/baz/),
                allowCustomizedBuiltInElements: true,
              },
            }
          ),
          '<foo-bar baz="foobar"></foo-bar><div is="foo-baz"></div>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<foo-bar baz="foobar" forbidden="true"></foo-bar><div is="foo-baz"></div>',
            {
              CUSTOM_ELEMENT_HANDLING: {
                tagNameCheck: (tagName) => tagName.match(/-bar$/),
                attributeNameCheck: (attr) => attr.match(/baz/),
                allowCustomizedBuiltInElements: true,
              },
            }
          ),
          '<foo-bar baz="foobar"></foo-bar><div is=""></div>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<my-paragraph><span slot="my-text">test</span></my-paragraph>',
            {
              CUSTOM_ELEMENT_HANDLING: { tagNameCheck: /-/u },
            }
          ),
          '<my-paragraph><span slot="my-text">test</span></my-paragraph>'
        );
      }
    );
    QUnit.test('Test dirty being an array', function (assert) {
      assert.equal(
        DOMPurify.sanitize(['<a>123<b>456</b></a>']),
        '<a>123<b>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize(['<img src=', 'x onerror=alert(1)>']),
        '<img src=",x">'
      );
    });
    // cross-check that document.write into iframe works properly
    QUnit.test('XSS test: document.write() into iframe', function (assert) {
      const done = assert.async();
      window.xssed = false;
      var iframe = document.createElement('iframe');
      iframe.src = 'about:blank';
      iframe.onload = function () {
        iframe.contentDocument.write(
          '<script>window.alert=function(){parent.xssed=true;}</script><script>alert(1);</script>'
        );
        assert.equal(window.xssed, true, 'alert() was called but not detected');
        window.xssed = false;
        iframe.parentNode.removeChild(iframe);
        done();
      };
      document.body.appendChild(iframe);
    });
    // Check for isSupported property
    QUnit.test('DOMPurify property tests', function (assert) {
      assert.equal(typeof DOMPurify.isSupported, 'boolean');
    });
    // Test with a custom window object
    QUnit.test('DOMPurify custom window tests', function (assert) {
      assert.strictEqual(typeof DOMPurify(null).version, 'string');
      assert.strictEqual(DOMPurify(null).isSupported, false);
      assert.strictEqual(DOMPurify(null).sanitize, undefined);
      assert.strictEqual(typeof DOMPurify({}).version, 'string');
      assert.strictEqual(DOMPurify({}).isSupported, false);
      assert.strictEqual(DOMPurify({}).sanitize, undefined);
      assert.strictEqual(
        typeof DOMPurify({ document: 'not really a document' }).version,
        'string'
      );
      assert.strictEqual(
        DOMPurify({ document: 'not really a document' }).isSupported,
        false
      );
      assert.strictEqual(
        DOMPurify({ document: 'not really a document' }).sanitize,
        undefined
      );
      assert.strictEqual(typeof DOMPurify(window).version, 'string');
      assert.strictEqual(typeof DOMPurify(window).sanitize, 'function');
    });
    // Test to prevent security issues with pre-clobbered DOM
    QUnit.test(
      'sanitize() should not throw if the original document is clobbered _after_ DOMPurify has been instantiated',
      function (assert) {
        var evilNode = document.createElement('div');
        evilNode.innerHTML =
          '<img id="implementation"><img id="createNodeIterator"><img id="importNode"><img id="createElement">';
        document.body.appendChild(evilNode);
        try {
          // tests implementation and createNodeIterator
          var resultPlain = DOMPurify.sanitize('123');
          // tests importNode
          var resultImport = DOMPurify.sanitize('123', {
            RETURN_DOM: true,
            ADD_ATTR: ['shadowroot'],
          });
          // tests createElement
          var resultBody = DOMPurify.sanitize('123<img id="body">');
        } finally {
          // clean up before doing the actual assertions, otherwise qunit/jquery/etc might blow up
          document.body.removeChild(evilNode);
        }
        assert.equal(resultPlain, '123');
        assert.equal(resultImport.ownerDocument, document);
        assert.equal(resultBody, '123<img>');
      }
    );
    // Test to check against a hang in MSIE (#89)
    QUnit.test(
      'sanitize() should not hang on MSIE when hook changes textContent',
      function (assert) {
        DOMPurify.addHook('afterSanitizeElements', function (node) {
          if (node.nodeType && node.nodeType === document.TEXT_NODE) {
            node.textContent = 'foo';
          }
          return node;
        });
        var dirty =
          '<div><p>This is a beatufiul text</p><p>This is too</p></div>';
        var modified = '<div><p>foo</p><p>foo</p></div>';
        assert.equal(DOMPurify.sanitize(dirty), modified);
        DOMPurify.removeHooks('afterSanitizeElements');
      }
    );
    // Tests to ensure that a configuration can be set and cleared
    QUnit.test(
      'ensure that a persistent configuration can be set and cleared',
      function (assert) {
        var dirty = '<foobar>abc</foobar>';
        assert.equal(DOMPurify.sanitize(dirty), 'abc');
        DOMPurify.setConfig({ ADD_TAGS: ['foobar'] });
        assert.equal(DOMPurify.sanitize(dirty), '<foobar>abc</foobar>');
        DOMPurify.clearConfig();
        assert.equal(DOMPurify.sanitize(dirty), 'abc');
      }
    );
    // Test to ensure that a hook can add allowed tags / attributes on the fly
    QUnit.test(
      'ensure that a hook can add allowed tags / attributes on the fly',
      function (assert) {
        DOMPurify.addHook('uponSanitizeElement', function (node, data) {
          if (
            node.nodeName &&
            node.nodeName.match(/^\w+-\w+$/) &&
            !data.allowedTags[data.tagName]
          ) {
            data.allowedTags[data.tagName] = true;
          }
        });
        DOMPurify.addHook('uponSanitizeAttribute', function (node, data) {
          if (
            data.attrName &&
            data.attrName.match(/^\w+-\w+$/) &&
            !data.allowedAttributes[data.attrName]
          ) {
            data.allowedAttributes[data.attrName] = true;
          }
        });
        var dirty =
          '<p>HE<iframe></iframe><is-custom onload="alert(1)" super-custom="test" />LLO</p>';
        var modified =
          '<p>HE<is-custom super-custom="test">LLO</is-custom></p>';
        assert.equal(DOMPurify.sanitize(dirty), modified);
        DOMPurify.removeHooks('uponSanitizeElement');
        DOMPurify.removeHooks('uponSanitizeAttribute');
      }
    );
    // Test to ensure that if input[type=file] is badlisted and flagged as an
    // attribute not to keep via hookEvent.keepAttr, it should be removed despite
    // it being an issue of being able to programmatically add it back in Safari.
    QUnit.test(
      'ensure that input[type=file] is removed via hookEvent keepAttr',
      function (assert) {
        DOMPurify.addHook('uponSanitizeAttribute', function (node, data) {
          if (
            node.nodeName == 'INPUT' &&
            node.getAttribute('type') &&
            node.getAttribute('type') == 'file'
          ) {
            data.keepAttr = false;
          }
        });
        var dirty = '<input type="file" />';
        var modified = '<input>';
        if (window.name == 'nodejs') {
          assert.equal(DOMPurify.sanitize(dirty), modified);
        } else {
          assert.expect(0);
        }
        DOMPurify.removeHooks('uponSanitizeAttribute');
      }
    );
    QUnit.test(
      'sanitize() should allow unknown protocols when ALLOW_UNKNOWN_PROTOCOLS is true',
      function (assert) {
        var dirty =
          '<div><a href="spotify:track:12345"><img src="cid:1234567"></a></div>';
        assert.equal(
          dirty,
          DOMPurify.sanitize(dirty, { ALLOW_UNKNOWN_PROTOCOLS: true })
        );
      }
    );

    QUnit.test(
      'sanitize() should not allow javascript when ALLOW_UNKNOWN_PROTOCOLS is true',
      function (assert) {
        var dirty =
          '<div><a href="javascript:alert(document.title)"><img src="cid:1234567"/></a></div>';
        var modified = '<div><a><img src="cid:1234567"></a></div>';
        assert.equal(
          modified,
          DOMPurify.sanitize(dirty, { ALLOW_UNKNOWN_PROTOCOLS: true })
        );
      }
    );

    QUnit.test(
      'Regression-Test to make sure #166 stays fixed',
      function (assert) {
        var dirty = '<p onFoo="123">HELLO</p>';
        var modified = '<p>HELLO</p>';
        assert.equal(
          modified,
          DOMPurify.sanitize(dirty, { ALLOW_UNKNOWN_PROTOCOLS: true })
        );
      }
    );

    // Test 1 to check if the element count in DOMPurify.removed is correct
    QUnit.test(
      'DOMPurify.removed should contain one element',
      function (assert) {
        var dirty =
          '<svg onload=alert(1)><filter><feGaussianBlur /></filter></svg>';
        DOMPurify.sanitize(dirty);
        assert.contains(DOMPurify.removed.length, [1, 2]); // IE removes two
      }
    );

    // Test 2 to check if the element count in DOMPurify.removed is correct
    QUnit.test(
      'DOMPurify.removed should contain two elements',
      function (assert) {
        var dirty =
          '1<script>alert(1)</script><svg onload=alert(1)><filter><feGaussianBlur /></filter></svg>';
        DOMPurify.sanitize(dirty);
        assert.contains(DOMPurify.removed.length, [2, 3]); // IE removed three
      }
    );

    // Test 3 to check if the element count in DOMPurify.removed is correct
    QUnit.test('DOMPurify.removed should be correct', function (assert) {
      var dirty = '<img src=x onerror="alert(1)">';
      DOMPurify.sanitize(dirty);
      assert.equal(DOMPurify.removed.length, 1);
    });

    // Test 4 to check that DOMPurify.removed is correct in SAFE_FOR_TEMLATES mode
    QUnit.test(
      'DOMPurify.removed should be correct in SAFE_FOR_TEMPLATES mode',
      function (assert) {
        var dirty = '<a>123{{456}}</a>';
        DOMPurify.sanitize(dirty, {
          WHOLE_DOCUMENT: true,
          SAFE_FOR_TEMPLATES: true,
        });
        assert.equal(DOMPurify.removed.length, 1);
      }
    );

    // Test 5 to check that DOMPurify.removed is correct in SAFE_FOR_TEMLATES mode
    QUnit.test(
      'DOMPurify.removed should be correct in SAFE_FOR_TEMPLATES mode',
      function (assert) {
        var dirty = '<a>123{{456}}<b>456{{789}}</b></a>';
        DOMPurify.sanitize(dirty, {
          WHOLE_DOCUMENT: true,
          SAFE_FOR_TEMPLATES: true,
        });
        assert.equal(DOMPurify.removed.length, 2);
      }
    );

    // Test 6 to check that DOMPurify.removed is correct in SAFE_FOR_TEMLATES mode
    QUnit.test(
      'DOMPurify.removed should be correct in SAFE_FOR_TEMPLATES mode',
      function (assert) {
        var dirty = '<img src=1 width="{{123}}">';
        DOMPurify.sanitize(dirty, {
          WHOLE_DOCUMENT: true,
          SAFE_FOR_TEMPLATES: true,
        });
        assert.equal(DOMPurify.removed.length, 1);
      }
    );

    // Test 7 to check that DOMPurify.removed is correct
    QUnit.test('DOMPurify.removed should be correct', function (assert) {
      var dirty = '<option><iframe></select><b><script>alert(1)</script>';
      DOMPurify.sanitize(dirty);
      assert.equal(DOMPurify.removed.length, 1);
    });

    // Test 8 to check that DOMPurify.removed is correct if tags are clean
    QUnit.test(
      'DOMPurify.removed should not contain elements if tags are permitted',
      function (assert) {
        var dirty = '<a>123</a>';
        DOMPurify.sanitize(dirty);
        assert.equal(DOMPurify.removed.length, 0);
      }
    );

    // Test 9 to check that DOMPurify.removed is correct if the tags and attributes are clean
    QUnit.test(
      'DOMPurify.removed should not contain elements if all tags and attrs are permitted',
      function (assert) {
        var dirty = '<img src=x>';
        DOMPurify.sanitize(dirty);
        assert.equal(DOMPurify.removed.length, 0);
      }
    );

    // Test 10 to check that DOMPurify.removed does not have false positive elements in SAFE_FOR_TEMLATES mode
    QUnit.test(
      'DOMPurify.removed should not contain elements for valid data in SAFE_FOR_TEMLATES mode',
      function (assert) {
        var dirty = '1';
        DOMPurify.sanitize(dirty, {
          WHOLE_DOCUMENT: true,
          SAFE_FOR_TEMPLATES: true,
        });
        assert.equal(DOMPurify.removed.length, 0);
      }
    );

    // Test 11 to check that DOMPurify.removed does not have false positive elements
    QUnit.test(
      'DOMPurify.removed should not contain elements for valid data',
      function (assert) {
        var dirty = '1';
        DOMPurify.sanitize(dirty, {
          WHOLE_DOCUMENT: true,
        });
        assert.equal(DOMPurify.removed.length, 0);
      }
    );
    // Tests to make sure that the node scanning feature delivers acurate results on all browsers
    QUnit.test(
      'DOMPurify should deliver acurate results when sanitizing nodes 1',
      function (assert) {
        var clean = DOMPurify.sanitize(document.createElement('td'));
        assert.equal(clean, '<td></td>');
      }
    );
    QUnit.test(
      'DOMPurify should deliver accurate results when sanitizing nodes 2',
      function (assert) {
        var clean = DOMPurify.sanitize(document.createElement('td'), {
          RETURN_DOM: true,
        });
        assert.equal(clean.outerHTML, '<body><td></td></body>');
      }
    );
    // Test to make sure that URI_safe attributes can be configured too
    QUnit.test(
      'DOMPurify should allow to define URI safe attributes',
      function (assert) {
        var clean = DOMPurify.sanitize('<b typeof="bla:h">123</b>', {
          ALLOWED_ATTR: ['typeof'],
          ADD_URI_SAFE_ATTR: ['typeof'],
        });
        assert.equal(clean, '<b typeof="bla:h">123</b>');
      }
    );
    // Test to make sure that URI_safe attributes don't persist, see #327
    QUnit.test(
      'DOMPurify should not persist URI safe attributes',
      function (assert) {
        var clean = DOMPurify.sanitize('<b typeof="bla:h">123</b>', {
          ALLOWED_ATTR: ['typeof'],
          ADD_URI_SAFE_ATTR: ['typeof'],
        });
        var clean = DOMPurify.sanitize('<b typeof="bla:h">123</b>', {
          ALLOWED_ATTR: ['typeof'],
        });
        assert.equal(clean, '<b>123</b>');
      }
    );
    // Test to make sure that URI_safe attributes don't overwrite default, see #366
    QUnit.test(
      'DOMPurify should not overwrite default URI safe attributes',
      function (assert) {
        var clean = DOMPurify.sanitize(
          '<div poster="x:y" style="color: red">Test</div>',
          { ADD_URI_SAFE_ATTR: ['poster'] }
        );
        assert.contains(clean, [
          '<div style="color: red" poster="x:y">Test</div>',
          '<div style="color: red;" poster="x:y">Test</div>',
        ]);

        clean = DOMPurify.sanitize(
          '<div poster="x:y" style="color: red">Test</div>'
        );
        assert.contains(clean, [
          '<div style="color: red">Test</div>',
          '<div style="color: red;">Test</div>',
        ]);
      }
    );
    // Test to make sure that empty HTML doesn't return null on MSIE11 (#198)
    QUnit.test(
      "Empty HTML shouldn't return null on MSIE11 in RETURN_DOM_FRAGMENT mode",
      function (assert) {
        var clean = DOMPurify.sanitize('', {
          RETURN_DOM: true,
          RETURN_DOM_FRAGMENT: true,
        });
        assert.equal(typeof clean, 'object');
      }
    );
    // Tests to make sure that FORCE_BODY pushes elements to document.body (#199)
    QUnit.test(
      'FORCE_BODY needs to push some elements to document.body',
      function (assert) {
        var clean = DOMPurify.sanitize('<style>123</style>', {
          FORCE_BODY: true,
        });
        assert.equal(clean, '<style>123</style>');
      }
    );
    QUnit.test(
      'FORCE_BODY needs to push some elements to document.body',
      function (assert) {
        var clean = DOMPurify.sanitize('<script>123</script>', {
          FORCE_BODY: true,
          ADD_TAGS: ['script'],
        });
        assert.equal(clean, '<script>123</script>');
      }
    );
    QUnit.test(
      'FORCE_BODY needs to push some elements to document.body',
      function (assert) {
        var clean = DOMPurify.sanitize(' AAAAA', { FORCE_BODY: true });
        assert.equal(clean, ' AAAAA');
      }
    );
    QUnit.test(
      'Lack of FORCE_BODY still preserves leading whitespace',
      function (assert) {
        var clean = DOMPurify.sanitize(' <b>AAAAA</b>', { FORCE_BODY: false });
        assert.equal(clean, ' <b>AAAAA</b>');
      }
    );
    QUnit.test(
      'Lack of FORCE_BODY needs to push some elements to document.head',
      function (assert) {
        var clean = DOMPurify.sanitize('<style>123</style>', {
          FORCE_BODY: false,
        });
        assert.equal(clean, '');
      }
    );

    // Regression: GHSA-c2j3-45gr-mqc4. A custom element kept via
    // CUSTOM_ELEMENT_HANDLING must run through afterSanitizeElements just
    // like a normal allowlisted element, so a security policy layered in
    // that hook is not silently skipped for kept custom elements.
    QUnit.test(
      'afterSanitizeElements fires on kept custom elements CVE-2026-66010',
      function (assert) {
        var seen = [];
        DOMPurify.addHook('afterSanitizeElements', function (node) {
          if (node.tagName) {
            seen.push(node.tagName.toLowerCase());
          }
        });
        DOMPurify.sanitize('<x-keep>a</x-keep><div>b</div>', {
          CUSTOM_ELEMENT_HANDLING: { tagNameCheck: /^x-/ },
        });
        DOMPurify.removeAllHooks();
        assert.ok(
          seen.indexOf('x-keep') !== -1,
          'hook must fire on kept custom element, saw: ' + seen.join(',')
        );
        assert.ok(seen.indexOf('div') !== -1, 'hook still fires on normal element');
      }
    );

    QUnit.test(
      'afterSanitizeElements policy applies uniformly to custom elements CVE-2026-66010',
      function (assert) {
        DOMPurify.addHook('afterSanitizeElements', function (node) {
          if (node.hasAttribute && node.hasAttribute('data-bio')) {
            node.removeAttribute('data-bio');
          }
        });
        var clean = DOMPurify.sanitize(
          '<div data-bio="x"></div><x-bio data-bio="x"></x-bio>',
          { CUSTOM_ELEMENT_HANDLING: { tagNameCheck: /^x-/ } }
        );
        DOMPurify.removeAllHooks();
        assert.equal(clean, '<div></div><x-bio></x-bio>');
      }
    );

    QUnit.test(
      'afterSanitizeElements policy applies to function tagNameCheck custom elements CVE-2026-66010',
      function (assert) {
        DOMPurify.addHook('afterSanitizeElements', function (node) {
          if (node.hasAttribute && node.hasAttribute('data-bio')) {
            node.removeAttribute('data-bio');
          }
        });
        var clean = DOMPurify.sanitize(
          '<div data-bio="x"></div><x-bio data-bio="x"></x-bio>',
          {
            CUSTOM_ELEMENT_HANDLING: {
              tagNameCheck: function (tagName) {
                return tagName.indexOf('x-') === 0;
              },
            },
          }
        );
        DOMPurify.removeAllHooks();
        assert.equal(clean, '<div></div><x-bio></x-bio>');
      }
    );

    QUnit.test(
      'afterSanitizeElements can remove a kept custom element CVE-2026-66010',
      function (assert) {
        DOMPurify.addHook('afterSanitizeElements', function (node) {
          if (node.tagName && node.tagName.toLowerCase() === 'x-evil') {
            node.parentNode.removeChild(node);
          }
        });
        var clean = DOMPurify.sanitize('<x-evil>a</x-evil><x-ok>b</x-ok>', {
          CUSTOM_ELEMENT_HANDLING: { tagNameCheck: /^x-/ },
        });
        DOMPurify.removeAllHooks();
        assert.equal(clean, '<x-ok>b</x-ok>');
      }
    );

    QUnit.test(
      'kept custom element attributes are still sanitized CVE-2026-66010',
      function (assert) {
        var clean = DOMPurify.sanitize(
          '<x-a onclick="alert(1)" href="javascript:alert(1)"><img src=x onerror=alert(1)></x-a>',
          { CUSTOM_ELEMENT_HANDLING: { tagNameCheck: /^x-/ } }
        );
        assert.notOk(/onclick/i.test(clean), 'event handler stripped');
        assert.notOk(/javascript:/i.test(clean), 'javascript: URI stripped');
        assert.notOk(/onerror/i.test(clean), 'child payload sanitized');
      }
    );

    // Test to make sure that ALLOW_ARIA_ATTR is working as expected (#198)
    QUnit.test('Config-Flag tests: ALLOW_ARIA_ATTR', function (assert) {
      assert.contains(
        DOMPurify.sanitize('<a aria-abc="foo" href="#">abc</a>', {
          ALLOW_ARIA_ATTR: true,
        }),
        [
          '<a aria-abc="foo" href="#">abc</a>',
          '<a href="#" aria-abc="foo">abc</a>',
        ]
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" aria-aöü="foo">abc</a>', {
          ALLOW_ARIA_ATTR: true,
        }),
        '<a href="#">abc</a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" aria-abc="foo">abc</a>', {
          ALLOW_ARIA_ATTR: false,
        }),
        '<a href="#">abc</a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" aria-äöü="foo">abc</a>', {
          ALLOW_ARIA_ATTR: false,
        }),
        '<a href="#">abc</a>'
      );
    });
    QUnit.test(
      'Config-Flag tests: USE_PROFILES ALLOWED_ATTR must not inherit from polluted prototypes CVE-2026-65913',
      function (assert) {
        Object.prototype.onerror = true;
        try {
          var clean = DOMPurify.sanitize('<img src="x" onerror="alert(1)">', {
            USE_PROFILES: {},
            ADD_TAGS: ['img'],
          });
          assert.equal(clean.indexOf('onerror'), -1);
          assert.equal(clean, '<img>');
        } finally {
          delete Object.prototype.onerror;
        }
      }
    );
    QUnit.test('Config-Flag tests: USE_PROFILES', function (assert) {
      assert.equal(
        DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: { html: false } }),
        'HELLO'
      );
      assert.equal(
        DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: { html: true } }),
        '<h1>HELLO</h1>'
      );
      assert.contains(
        DOMPurify.sanitize('<h1>HELLO</h1><math></math>', {
          USE_PROFILES: { html: true, mathMl: true },
        }),
        [
          '<h1>HELLO</h1>',
          '<h1>HELLO</h1><math></math>',
          '<h1>HELLO</h1><math></math>',
        ]
      );
      assert.contains(
        DOMPurify.sanitize('<h1>HELLO</h1><math><mi></mi></math>', {
          USE_PROFILES: { html: true, mathMl: true },
        }),
        [
          '<h1>HELLO</h1>',
          '<h1>HELLO</h1><math><mi></mi></math>',
          '<h1>HELLO</h1><math></math>',
        ]
      );
      assert.contains(
        DOMPurify.sanitize('<h1>HELLO</h1><math><mi></mi></math>', {
          USE_PROFILES: { html: true, mathMl: true },
          FORBID_TAGS: ['mi'],
        }),
        [
          '<h1>HELLO</h1>',
          '<h1>HELLO</h1><math></math>',
          '<h1>HELLO</h1><math></math>',
        ]
      );
      assert.contains(
        DOMPurify.sanitize('<h1>HELLO</h1><math class="foo"><mi></mi></math>', {
          USE_PROFILES: { html: true, mathMl: true },
          FORBID_ATTR: ['class'],
        }),
        [
          '<h1>HELLO</h1>',
          '<h1>HELLO</h1><math><mi></mi></math>',
          '<h1>HELLO</h1><math></math>',
        ]
      );
      assert.equal(
        DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: { bogus: true } }),
        'HELLO'
      );
      assert.equal(
        DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: 123 }),
        'HELLO'
      );
      assert.equal(
        DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: [] }),
        'HELLO'
      );
      assert.contains(
        DOMPurify.sanitize('<svg><rect height="50"></rect></svg>', {
          USE_PROFILES: { svg: true },
        }),
        [
          '',
          '<svg><rect height="50"></rect></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg"><rect height="50" /></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg" />',
        ]
      );
      assert.contains(
        DOMPurify.sanitize(
          '<svg><feBlend in="SourceGraphic" mode="multiply" /></svg>',
          {
            USE_PROFILES: { svgFilters: true },
            ADD_TAGS: ['svg'],
          }
        ),
        [
          '<svg><feblend in="SourceGraphic" mode="multiply"></feblend></svg>',
          '<svg><feblend mode="multiply" in="SourceGraphic"></feblend></svg>',
          '<svg><feBlend mode="multiply" in="SourceGraphic"></feBlend></svg>',
          '<svg><feBlend mode="multiply" in="SourceGraphic"></feBlend></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg"><feBlend in="SourceGraphic" mode="multiply" /></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg" />',
        ]
      );
      assert.contains(
        DOMPurify.sanitize(
          '<svg><style>.some-class {fill: #fff}</style></svg>',
          {
            USE_PROFILES: { svg: true },
          }
        ),
        [
          '',
          '<svg><style>.some-class {fill: #fff}</style></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg"><style>.some-class {fill: #fff}</style></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg" />',
        ]
      );
      assert.contains(
        DOMPurify.sanitize('<svg><text>SEE ME</text></svg>', {
          USE_PROFILES: { svg: true },
          KEEP_CONTENT: false,
        }),
        [
          '',
          '<svg><text>SEE ME</text></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg"><text>SEE ME</text></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg" />',
        ]
      );
      assert.equal(
        DOMPurify.sanitize('<span>SEE ME</span>', {
          USE_PROFILES: { html: true },
          KEEP_CONTENT: false,
        }),
        '<span>SEE ME</span>'
      );
      assert.equal(
        DOMPurify.sanitize('<div></div>', {
          USE_PROFILES: { svg: true },
          ADD_TAGS: ['div'],
        }),
        '<div></div>'
      );
      assert.contains(
        DOMPurify.sanitize('<svg keep="me"></svg>', {
          USE_PROFILES: { svg: true },
          ADD_ATTR: ['keep'],
        }),
        [
          '',
          '<svg keep="me"></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg" keep="me" />',
        ]
      );
    });
    QUnit.test('Config-Flag tests: ALLOWED_URI_REGEXP', function (assert) {
      var tests = [
        {
          test: '<img src="https://i.imgur.com/hkfpOUu.gifv">',
          expected: '<img src="https://i.imgur.com/hkfpOUu.gifv">',
        },
        {
          test: '<img src="http://i.imgur.com/WScAnHr.jpg">',
          expected: '<img src="http://i.imgur.com/WScAnHr.jpg">',
        },
        {
          test:
            '<img src="blob:https://localhost:3000/c4ea3ec6-9f22-4d08-af6f-d79e78a0a7a7">',
          expected: '<img>',
        },
        {
          test: '<a href="mailto:demo@example.com">demo</a>',
          expected: '<a>demo</a>',
        },
      ];
      tests.forEach(function (test) {
        var str = DOMPurify.sanitize(test.test, {
          ALLOWED_URI_REGEXP: /^(?:(?:(?:f|ht)tps?):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i,
        });
        assert.equal(str, test.expected);
      });
    });
    QUnit.test(
      'Avoid freeze when using tables and ALLOW_TAGS',
      function (assert) {
        var clean = DOMPurify.sanitize('<table><tr><td></td></tr></table>', {
          ALLOW_TAGS: ['table', 'tr', 'td'],
        });
        assert.equal(clean, '<table><tbody><tr><td></td></tr></tbody></table>');
      }
    );
    QUnit.test(
      'Avoid XSS with ALLOW_TAGS permitting noembed, noscript',
      function (assert) {
        var clean = DOMPurify.sanitize(
          "a<noembed><p id='</noembed><img src=x onerror=alert(1)>'></p></noembed>",
          { ADD_TAGS: ['noembed'] }
        );
        assert.contains(clean, [
          'a<noembed><p id=\'</noembed><img src="x">\'&gt;<p></p>',
          'a',
          'a<noembed>&lt;p id=\'</noembed><img src="x">\'&gt;<p></p>',
          'a<noembed><p id="&lt;/noembed&gt;&lt;img src=x onerror=alert(1)&gt;"></p></noembed>',
          'a<noembed></noembed>',
          'a<img src="x">\'&gt;<p></p>',
        ]);
      }
    );
    QUnit.test(
      'Avoid mXSS in Chrome 77 and above using SVG',
      function (assert) {
        var clean = DOMPurify.sanitize('<svg></p><style><g title="</style>');
        assert.contains(clean, [
          '',
          '<svg></svg><p></p><style><g title="</style>',
          '<p></p><style><g title="</style>',
          '<svg></svg><p></p>',
          '<svg><style></style></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg"><style /></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg"><style /></svg></svg>',
        ]);
      }
    );
    QUnit.test(
      'Avoid mXSS in Chrome 77 and above using HTML',
      function (assert) {
        var clean = DOMPurify.sanitize('<svg></p><title><a href="</title>qqq');
        assert.contains(clean, [
          '',
          '<svg></svg><p></p><title>&lt;a href="</title>qqq<img src="">"&gt;',
          '<svg></svg><p></p><title>&lt;a href="</title>qqq',
          '<p></p><title>&lt;a href="</title>qqq',
          '<svg></svg><p></p>qqq',
          '<svg><title></title></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg"><title /></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg"><title /></svg></svg>',
        ]);
      }
    );
    QUnit.test(
      'Test for correct return value when RETURN_TRUSTED_TYPE is true',
      function (assert) {
        var clean = DOMPurify.sanitize('<b>hello goodbye</b>', {
          RETURN_TRUSTED_TYPE: true,
        });
        var type = typeof clean;
        assert.contains(type, ['TrustedHTML', 'string', 'object']);
      }
    );
    QUnit.test(
      'Test for correct return value when RETURN_TRUSTED_TYPE is false',
      function (assert) {
        var clean = DOMPurify.sanitize('<b>hello goodbye</b>', {
          RETURN_TRUSTED_TYPE: false,
        });
        var type = typeof clean;
        assert.equal(type, 'string');
      }
    );
    QUnit.test(
      'Test for correct return value when RETURN_TRUSTED_TYPE is not set',
      function (assert) {
        var clean = DOMPurify.sanitize('<b>hello goodbye</b>');
        var type = typeof clean;
        assert.equal(type, 'string');
      }
    );
    QUnit.test(
      'Test for DoS coming from table sanitization 1/2 See #365',
      function (assert) {
        var config = { FORBID_TAGS: ['tbody'] };
        var clean = DOMPurify.sanitize(
          '<table><tbody><tr><td>test</td></tr></tbody></table>',
          config
        );
        assert.equal(
          clean,
          '<table><tbody><tr><td>test</td></tr></tbody></table>'
        );
      }
    );
    QUnit.test(
      'Test for DoS coming from table sanitization 2/2 See #365',
      function (assert) {
        var config = {
          ALLOWED_TAGS: [
            'b',
            'strong',
            'i',
            'italic',
            'div',
            'p',
            'span',
            'ul',
            'li',
            'ol',
            'a',
            'img',
            'br',
            'tr',
            'td',
            'th',
            'table',
            'h1',
            'h2',
            'h3',
            'h4',
            'h5',
            'h6',
          ],
          ALLOW_DATA_ATTR: false,
          ALLOWED_ATTR: ['src', 'class', 'target', 'href'],
        };
        var clean = DOMPurify.sanitize(
          '<table><colgroup><col></col></colgroup><tbody><tr><td >test</td></tr></tbody></table>',
          config
        );
        assert.equal(
          clean,
          '<table><tbody><tr><td>test</td></tr></tbody></table>'
        );
      }
    );
    QUnit.test(
      'Test for less agressive mXSS handling, See #369',
      function (assert) {
        var config = {
          FORBID_TAGS: ['svg', 'math'],
        };
        var clean = DOMPurify.sanitize(
          '<b data-test="<span>content</span>"></b>',
          config
        );
        assert.contains(clean, [
          '<b data-test="<span>content</span>"></b>',
          '<b data-test="&lt;span&gt;content&lt;/span&gt;"></b>',
        ]);
      }
    );
    QUnit.test(
      'Test against mXSS using text integration points and removal 1/2',
      function (assert) {
        var config = {
          FORBID_TAGS: ['mi'],
        };
        var clean = DOMPurify.sanitize(
          '<math><mi><b><style><b title="</style><iframe onload&#x3d;alert(1)<!--"></style>',
          config
        );
        assert.contains(clean, [
          '<math><b><style><b title="</style></b></math>',
          '<math></math>',
          '',
        ]);
      }
    );
    QUnit.test(
      'Test against mXSS using text integration points and removal 2/2',
      function (assert) {
        var config = {
          ADD_TAGS: ['xmp'],
        };
        var clean = DOMPurify.sanitize(
          "x<noframes><svg><b><xmp><b title='</xmp><img>",
          config
        );
        assert.contains(clean, ['x']);
      }
    );
    QUnit.test(
      'Test against insecure behavior in jQUery v3.0 and newer 1/2',
      function (assert) {
        var config = {};
        var clean = DOMPurify.sanitize(
          '<img x="/><img src=x onerror=alert(1)>" y="<x">',
          config
        );
        assert.contains(clean, [
          '<img y="<x" x="/><img src=x onerror=alert(1)>">', // jsdom
          '<img y="<x">',
          '<img y="&lt;x">',
          '<img y="<x">',
          "<img x=\"/><img src=x onerror=alert(1)>\" y=\"<x\">",
		  "<img y=\"&lt;x\" x=\"/&gt;&lt;img src=x onerror=alert(1)&gt;\">"
        ]);
      }
    );
    QUnit.test(
      'Test against insecure behavior in jQUery v3.0 and newer 2/2',
      function (assert) {
        var config = {};
        var clean = DOMPurify.sanitize(
          "a<noscript><p id='><noscript /><img src=x onerror=alert(1)>'></noscript>",
          config
        );
        assert.contains(clean, [
          "a<noscript>&lt;p id='>&lt;noscript />&lt;img src=x onerror=alert(1)>'></noscript>", // jsdom
          'a<noscript><p></p></noscript>',
          'a<p></p>',
          'a',
        ]);
      }
    );
    QUnit.test(
      'Test against data URIs in anchors without proper config flag',
      function (assert) {
        var clean = DOMPurify.sanitize(
          '<a href="data:image/gif;base64,123">icon.gif</a>'
        );
        assert.equal(clean, '<a>icon.gif</a>');
      }
    );
    QUnit.test(
      'Test against data URIs in anchors using proper config flag',
      function (assert) {
        var clean = DOMPurify.sanitize(
          '<a href="data:image/gif;base64,123">icon.gif</a>',
          {
            ADD_DATA_URI_TAGS: ['a', 'b'],
          }
        );
        assert.equal(clean, '<a href="data:image/gif;base64,123">icon.gif</a>');
      }
    );
    QUnit.test(
      'Test against Unicode tag names and proper removal',
      function (assert) {
        var clean = DOMPurify.sanitize('<svg><blocKquote>foo</blocKquote>');
        assert.contains(clean, [
          '<svg></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg" />',
        ]);

        var clean = DOMPurify.sanitize('<svg><blocKquote>foo</blocKquote>');
        assert.contains(clean, [
          '<svg></svg><blockquote>foo</blockquote>',
          '<svg><blockquote>foo</blockquote></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg" /><blockquote>foo</blockquote>',
        ]);
      }
    );
    QUnit.test(
      'Test protection from prototype pollution attacks 1/2',
      function (assert) {
        const obj = JSON.parse(
          '{"ALLOWED_ATTR":["onerror","src"], "documentMode":9}'
        );
        try {
          for (let [k, v] of Object.entries(obj)) {
            Object.prototype[k] = v;
          }
        } catch (e) {}
        var clean = DOMPurify.sanitize('<img src=x onerror=alert(1)>');
        assert.equal(clean, '<img src="x">');
      }
    );
    QUnit.test(
      'Test protection from prototype pollution attacks 2/2',
      function (assert) {
        var obj = {};
        obj.__proto__.hasOwnProperty = Object;
        obj.constructor.prototype.ALLOWED_ATTR = ["src", "onerror"];
        var clean = DOMPurify.sanitize('<img src=x onerror=alert(1)>');
        assert.equal(clean, '<img src="x">');
      }
    );
    QUnit.test('Test if namespaces are properly enforced', function (assert) {
      var tests = [
        {
          test:
            '<svg><desc><canvas></canvas><textarea></textarea></desc></svg>',
          expected: [
            '<svg><desc></desc></svg>',
            '<svg xmlns="http://www.w3.org/2000/svg"><desc></desc></svg>',
            '<svg xmlns="http://www.w3.org/2000/svg" />',
            "<svg xmlns=\"http://www.w3.org/2000/svg\"><desc /></svg>"
          ],
        },
        {
          test: '<svg><canvas></canvas><textarea></textarea></svg>',
          expected: [
            '<svg></svg>',
            '<svg xmlns="http://www.w3.org/2000/svg" />',
            "<svg xmlns=\"http://www.w3.org/2000/svg\"><title /></svg>"
          ],
        },
        {
          test: '<math><canvas></canvas><textarea></textarea></math>',
          expected: ['<math></math>'],
        },
        {
          test: '<math><mi><canvas></canvas><textarea></textarea></mi></math>',
          expected: [
            '<math><mi><canvas></canvas><textarea></textarea></mi></math>',
            '<math></math>',
          ],
        },
        {
          test: '<svg><math></math><title><math></math></title></svg>',
          expected: [
            '<svg><title></title></svg>',
            '<svg xmlns="http://www.w3.org/2000/svg" />',
            '<svg xmlns="http://www.w3.org/2000/svg"><title></title></svg>',
            "<svg xmlns=\"http://www.w3.org/2000/svg\"><title /></svg>"
          ],
        },
        {
          test: '<math><svg></svg><mi><svg></svg></mi></math>',
          expected: [
            '<math><mi><svg></svg></mi></math>',
            '<math><mi><svg xmlns="http://www.w3.org/2000/svg" /></mi></math>',
            '<math></math>',
          ],
        },
        {
          test: '<form><math><mi><mglyph></form><form>',
          expected: [
            '<form><math><mi><mglyph></mglyph></mi></math></form>',
            '<form><math></math></form>',
          ],
        },
      ];
      tests.forEach(function (test) {
        var clean = DOMPurify.sanitize(test.test);
        assert.contains(clean, test.expected);
      });
    });
    QUnit.test('Config-Flag tests: NAMESPACE', function (assert) {
      var tests = [
        {
          test: '<polyline points="0 0"></polyline>',
          config: { NAMESPACE: 'http://www.w3.org/2000/svg' },
          expected: [
            '<polyline points="0 0"></polyline>',
            '<polyline xmlns="http://www.w3.org/2000/svg" points="0 0"/>',
            '<polyline xmlns="http://www.w3.org/2000/svg" points="0,0" />',
            '',
          ],
        },
        {
          test: '<polyline points="0 0"></polyline>',
          config: { NAMESPACE: 'http://www.w3.org/1999/xhtml' },
          expected: ['', '<polyline points="0 0"></polyline>'], // IE10
        },
        {
          test: '<mi></mi>',
          config: { NAMESPACE: 'http://www.w3.org/1998/Math/MathML' },
          expected: [
            '<mi></mi>',
            '<mi xmlns="http://www.w3.org/1998/Math/MathML"></mi>',
            '<mi xmlns="http://www.w3.org/1998/Math/MathML"/>',
            '<mi xmlns="http://www.w3.org/1998/Math/MathML" />',
            '',
          ],
        },
        {
          test: '<polyline points="0 0"></polyline>',
          config: { NAMESPACE: 'http://www.w3.org/1998/Math/MathML' },
          expected: ['', '<polyline points="0 0"></polyline>'], // IE10
        },
        {
          test: '<mi></mi>',
          config: { NAMESPACE: 'http://www.w3.org/1999/xhtml' },
          expected: [''],
        },
      ];
      tests.forEach(function (test) {
        var clean = DOMPurify.sanitize(test.test, test.config);
        assert.contains(clean, test.expected);
      });
    });
    QUnit.test('Config-Flag tests: ALLOWED_NAMESPACES', function (assert) {
      const tests = [
        // Test when ALLOWED_NAMESPACES is not set, result is empty for XML with custom namespace
        {
          test:
            '<library xmlns="http://www.ibm.com/library"><name>Library 1</name></library>',
          config: {
            ALLOWED_TAGS: ['#text', 'library', 'name'],
            KEEP_CONTENT: false,
            PARSER_MEDIA_TYPE: 'application/xhtml+xml',
          },
          expected: '',
        },
        // Test with one custom namespace at the root (ie. all sub-nodes will inherit that namespace)
        {
          test:
            '<library xmlns="http://www.ibm.com/library"><name>Library 1</name><dirty onload="alert()" /></library>',
          config: {
            ALLOWED_NAMESPACES: ['http://www.ibm.com/library'],
            ALLOWED_TAGS: ['#text', 'library', 'name'],
            KEEP_CONTENT: false,
            PARSER_MEDIA_TYPE: 'application/xhtml+xml',
          },
          expected:
            '<library xmlns="http://www.ibm.com/library"><name>Library 1</name></library>',
        },
        // Test with one custom namespace at sub-node (root will default to HTML_NAMESPACE and should be kept)
        {
          test:
            '<city><library xmlns="http://www.ibm.com/library"><name>Library 1</name><dirty onload="alert()" /></library></city>',
          config: {
            ALLOWED_NAMESPACES: ['http://www.w3.org/1999/xhtml', 'http://www.ibm.com/library'],
            ALLOWED_TAGS: ['#text', 'city', 'library', 'name'],
            KEEP_CONTENT: false,
            PARSER_MEDIA_TYPE: 'application/xhtml+xml',
          },
          expected:
            '<city xmlns="http://www.w3.org/1999/xhtml"><library xmlns="http://www.ibm.com/library"><name>Library 1</name></library></city>',
        },
        // Test removal of namespaces not listed in ALLOWED_NAMESPACES when input has multiple namespaces
        {
          test:
            '<library xmlns="http://www.ibm.com/library" xmlns:bk="urn:loc.gov:books"><bk:name>Library 1</bk:name><dirty onload="alert()" /></library>',
          config: {
            ALLOWED_NAMESPACES: ['http://www.ibm.com/library'],
            ALLOWED_TAGS: ['library', 'bk:name'],
            KEEP_CONTENT: false,
            PARSER_MEDIA_TYPE: 'application/xhtml+xml',
          },
          expected: ['<library xmlns="http://www.ibm.com/library"/>', '<library xmlns="http://www.ibm.com/library" />']
        },
        // Test with multiple custom namespaces and prefixes in input
        {
          test:
            '<library xmlns="http://www.ibm.com/library" xmlns:bk="urn:loc.gov:books" xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata"><bk:name>Library 1<m:properties>Other Properties</m:properties></bk:name><dirty onload="alert()" /></library>',
          config: {
            ALLOWED_NAMESPACES: [
              'http://www.ibm.com/library',
              'urn:loc.gov:books',
              'http://schemas.microsoft.com/ado/2007/08/dataservices/metadata',
            ],
            ALLOWED_TAGS: ['#text', 'library', 'bk:name', 'm:properties'],
            KEEP_CONTENT: false,
            PARSER_MEDIA_TYPE: 'application/xhtml+xml',
          },
          expected:
            '<library xmlns="http://www.ibm.com/library"><bk:name xmlns:bk="urn:loc.gov:books">Library 1<m:properties xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata">Other Properties</m:properties></bk:name></library>',
        },
        // Test removal of elements mentioned in FORBID_TAGS even if their namespaces are allow-listed
        {
          test:
            '<library xmlns="http://www.ibm.com/library" xmlns:bk="urn:loc.gov:books" xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata"><bk:name>Library 1<m:properties>Other Properties</m:properties></bk:name><dirty onload="alert()" /></library>',
          config: {
            ADD_TAGS: ['library', 'bk:name'],
            ALLOWED_NAMESPACES: [
              'http://www.ibm.com/library',
              'urn:loc.gov:books',
              'http://schemas.microsoft.com/ado/2007/08/dataservices/metadata',
            ],
            FORBID_TAGS: ['m:properties'],
            KEEP_CONTENT: false,
            PARSER_MEDIA_TYPE: 'application/xhtml+xml',
          },
          expected:
            '<library xmlns="http://www.ibm.com/library"><bk:name xmlns:bk="urn:loc.gov:books">Library 1</bk:name></library>',
        },
      ];
      tests.forEach(function (test) {
        assert.contains(DOMPurify.sanitize(test.test, test.config), test.expected);
      });
    });
    QUnit.test('Config-Flag tests: PARSER_MEDIA_TYPE', function (assert) {
      const tests = [
        {
          test: '<A href="#">invalid</A><a TITLE="title" href="#">valid</a>',
          expected: {
            '': [
              '<a href="#">invalid</a><a href="#" title="title">valid</a>',
              '<a href="#">invalid</a><a title="title" href="#">valid</a>',
            ],
            'Application/xhtml+xml': [
              '<a href="#">invalid</a><a href="#" title="title">valid</a>',
              '<a href="#">invalid</a><a title="title" href="#">valid</a>',
            ],
            'application/xml': [
              '<a href="#">invalid</a><a href="#" title="title">valid</a>',
              '<a href="#">invalid</a><a title="title" href="#">valid</a>',
            ],
            'application/xhtml+xml': [
              '<a href="#">invalid</a><a href="#" title="title">valid</a>',
              'invalid<a xmlns="http://www.w3.org/1999/xhtml" href="#">valid</a>',
              'invalid<a xmlns="http://www.w3.org/1999/xhtml" href="#" TITLE="title">valid</a>',
            ],
            'text/html': [
              '<a href="#">invalid</a><a href="#" title="title">valid</a>',
              '<a href="#">invalid</a><a title="title" href="#">valid</a>',
            ],
            'text/xml': [
              '<a href="#">invalid</a><a href="#" title="title">valid</a>',
              '<a href="#">invalid</a><a title="title" href="#">valid</a>',
            ],
          },
        },
        {
          config: {
            WHOLE_DOCUMENT: true,
          },
          test: '<A href="#">invalid</A><a TITLE="title" href="#">valid</a>',
          expected: {
            'text/html': [
              '<html><head></head><body><a href="#">invalid</a><a href="#" title="title">valid</a></body></html>',
              '<html><head></head><body><a href="#">invalid</a><a title="title" href="#">valid</a></body></html>',
            ],
            'application/xhtml+xml': [
              '<html xmlns="http://www.w3.org/1999/xhtml"><head></head><body>invalid<a href="#">valid</a></body></html>',
              '<html xmlns="http://www.w3.org/1999/xhtml"><head /><body>invalid<a href="#">valid</a></body></html>',
              '<html xmlns="http://www.w3.org/1999/xhtml"><head></head><body>invalid<a href="#" TITLE="title">valid</a></body></html>',
            ],
          },
        },
      ];
      tests.forEach(function (test) {
        Object.keys(test.expected).forEach(function (type) {
          var config = test.config || {};
          config.PARSER_MEDIA_TYPE = type;
          var clean = DOMPurify.sanitize(test.test, config);
          assert.contains(clean, test.expected[type]);
        });
      });
    });

    QUnit.test(
      'Config-Flag tests: PARSER_MEDIA_TYPE + ALLOWED_TAGS/ALLOWED_ATTR',
      function (assert) {
        assert.contains(
          DOMPurify.sanitize(
            '<a href="#">abc</a><CustomTag customattr="bar" CustomAttr="foo"/>',
            {
              PARSER_MEDIA_TYPE: 'application/xhtml+xml',
              ALLOWED_TAGS: ['a', 'CustomTag'],
              ALLOWED_ATTR: ['href', 'CustomAttr'],
            }
          ),
          [
            '<a xmlns="http://www.w3.org/1999/xhtml" href="#">abc</a><CustomTag xmlns="http://www.w3.org/1999/xhtml" CustomAttr="foo"></CustomTag>',
            '<a xmlns="http://www.w3.org/1999/xhtml" href="#">abc</a><CustomTag xmlns="http://www.w3.org/1999/xhtml" CustomAttr="foo" customattr="foo"></CustomTag>',
            '<a xmlns="http://www.w3.org/1999/xhtml" href="#">abc</a><CustomTag xmlns="http://www.w3.org/1999/xhtml" CustomAttr="foo" />'
          ]
        );
      }
    );

    // An allowed <animate>/<set> must not be able to retarget a link's href:
    // attributeName values containing "href" are dropped. In XHTML mode the
    // attribute name keeps its case (attributeName), so the guard must not
    // compare it against 'attributename' only; with
    // values="x;javascript:..." the last list entry passes the URI check and
    // becomes the link's effective href (GHSA-c6gr-qvv4-5v3f).
    QUnit.test(
      'animated href is blocked in every parser mode (attributeName guard) (GHSA-c6gr-qvv4-5v3f)',
      function (assert) {
        var svgNs = 'xmlns="http://www.w3.org/2000/svg"';
        var animate =
          '<svg ' +
          svgNs +
          '><a id="q"><animate attributeName="href" ' +
          'values="x;javascript:alert(1)" dur="0.01s" fill="freeze"/>' +
          '<text x="10" y="40">click</text></a></svg>';
        var animateXlink =
          '<svg ' +
          svgNs +
          ' xmlns:xlink="http://www.w3.org/1999/xlink"><a id="q">' +
          '<animate attributeName="xlink:href" ' +
          'values="x;javascript:alert(1)" dur="0.01s" fill="freeze"/>' +
          '<text x="10" y="40">click</text></a></svg>';
        var set =
          '<svg ' +
          svgNs +
          '><a><set attributeName="href" to="x" fill="freeze"/>' +
          '<text>click</text></a></svg>';
        var animAttrs = ['values', 'dur', 'fill', 'x', 'y', 'id', 'to'];
        var configs = [
          {
            label: 'XHTML, camelCase ALLOWED_ATTR',
            cfg: {
              PARSER_MEDIA_TYPE: 'application/xhtml+xml',
              ALLOWED_TAGS: ['svg', 'a', 'animate', 'set', 'text'],
              ALLOWED_ATTR: ['attributeName'].concat(animAttrs),
            },
          },
          {
            label: 'XHTML, svg profile + ADD_ATTR',
            cfg: {
              PARSER_MEDIA_TYPE: 'application/xhtml+xml',
              USE_PROFILES: { svg: true },
              ADD_TAGS: ['animate', 'set'],
              ADD_ATTR: ['attributeName'].concat(animAttrs),
            },
          },
          {
            // Lets attributeName="xlink:href" through the URI check, so only
            // the attributeName guard stands between it and the link.
            label: 'XHTML, ALLOW_UNKNOWN_PROTOCOLS',
            cfg: {
              PARSER_MEDIA_TYPE: 'application/xhtml+xml',
              ALLOWED_TAGS: ['svg', 'a', 'animate', 'set', 'text'],
              ALLOWED_ATTR: ['attributeName'].concat(animAttrs),
              ALLOW_UNKNOWN_PROTOCOLS: true,
            },
          },
          {
            label: 'text/html',
            cfg: {
              ALLOWED_TAGS: ['svg', 'a', 'animate', 'set', 'text'],
              ALLOWED_ATTR: ['attributename'].concat(animAttrs),
            },
          },
        ];

        configs.forEach(function (config) {
          [animate, animateXlink, set].forEach(function (dirty) {
            var clean = DOMPurify.sanitize(dirty, config.cfg);
            assert.notOk(
              /attributename/i.test(clean),
              config.label + ': href-targeting attributeName removed: ' + clean
            );
          });
        });
      }
    );

    QUnit.test(
      'XHTML: attributeName that does not target href is kept (GHSA-c6gr-qvv4-5v3f)',
      function (assert) {
        // The guard must not over-strip ordinary SVG animations.
        var clean = DOMPurify.sanitize(
          '<svg xmlns="http://www.w3.org/2000/svg"><rect width="10" height="10">' +
            '<animate attributeName="opacity" values="0;1" dur="1s"/></rect></svg>',
          {
            PARSER_MEDIA_TYPE: 'application/xhtml+xml',
            USE_PROFILES: { svg: true },
            ADD_TAGS: ['animate'],
            ADD_ATTR: ['attributeName', 'values', 'dur'],
          }
        );
        assert.ok(
          /attributeName="opacity"/.test(clean),
          'non-href animation kept: ' + clean
        );
      }
    );

    QUnit.test(
      'XHTML: removed <foreignObject> drops its content like in HTML mode (GHSA-c6gr-qvv4-5v3f)',
      function (assert) {
        // FORBID_CONTENTS lists `foreignobject`; in XHTML mode the element is
        // spelled foreignObject, and its content used to be hoisted into the
        // SVG parent instead of being dropped.
        var dirty =
          '<svg xmlns="http://www.w3.org/2000/svg"><foreignObject>' +
          '<title>hoisted</title><desc>hoisted</desc>' +
          '</foreignObject></svg>';
        ['text/html', 'application/xhtml+xml'].forEach(function (type) {
          var clean = DOMPurify.sanitize(dirty, {
            PARSER_MEDIA_TYPE: type,
            USE_PROFILES: { svg: true },
          });
          assert.notOk(
            /hoisted/.test(clean),
            type + ': foreignObject content dropped: ' + clean
          );
        });
      }
    );

    QUnit.test('Test invalid xml', function (assert) {
      var tests = [
        {
          test: '',
          config: { NAMESPACE: 'http://www.w3.org/2000/svg' },
          expected: [''],
        },
        {
          test: '<!-->',
          config: { NAMESPACE: 'http://www.w3.org/2000/svg' },
          expected: ['', '<!-->'],
        },
        {
          test: '',
          config: { NAMESPACE: 'http://www.w3.org/1998/Math/MathML' },
          expected: [''],
        },
        {
          test: '<!-->',
          config: { NAMESPACE: 'http://www.w3.org/1998/Math/MathML' },
          expected: ['', '<!-->'],
        },
        {
          test: '',
          config: { NAMESPACE: 'http://www.w3.org/1999/xhtml' },
          expected: [''],
        },
        {
          test: '',
          config: {},
          expected: [''],
        },
        {
          test: '<!-->',
          config: { NAMESPACE: 'http://www.w3.org/1999/xhtml' },
          expected: ['', '<!-->'],
        },
        {
          test: '<!-->',
          config: {},
          expected: ['', '<!-->'],
        },
      ];
      tests.forEach(function (test) {
        var clean = DOMPurify.sanitize(test.test, test.config);
        assert.contains(clean, test.expected);
      });
    });

    QUnit.test(
      'Test namespace default to html after other namespace been used',
      function (assert) {
        var tests = [
          {
            test: '<br>',
            config: { NAMESPACE: 'http://www.w3.org/2000/svg' },
            expected: ['', '<br>'],
          },
          {
            test: '<br>',
            config: {},
            expected: ['<br>'],
          },
        ];
        tests.forEach(function (test) {
          var clean = DOMPurify.sanitize(test.test, test.config);
          assert.contains(clean, test.expected);
        });
      }
    );

    QUnit.test('Test non-html input after empty input', function (assert) {
      var tests = [
        {
          test: '',
          config: { NAMESPACE: 'http://www.w3.org/2000/svg' },
          expected: [''],
        },
        {
          test: '<polyline points="0 0"></polyline>',
          config: { NAMESPACE: 'http://www.w3.org/2000/svg' },
          expected: [
            '<polyline points="0 0"></polyline>',
            '<polyline xmlns="http://www.w3.org/2000/svg" points="0 0"/>',
            '<polyline xmlns="http://www.w3.org/2000/svg" points="0,0" />',
            '',
          ],
        },
      ];
      tests.forEach(function (test) {
        var clean = DOMPurify.sanitize(test.test, test.config);
        assert.contains(clean, test.expected);
      });
    });

    QUnit.test('removeHook returns hook function', function (assert) {
      const entryPoint = 'afterSanitizeAttributes';
      const dirty = '<div class="hello"></div>';
      const expected = '<div class="world"></div>';

      DOMPurify.addHook(entryPoint, function (node) {
        return node.setAttribute('class', 'world');
      });
      assert.equal(DOMPurify.sanitize(dirty), expected);

      // remove hook and keep it
      const hookFunction = DOMPurify.removeHook(entryPoint);
      assert.equal(DOMPurify.sanitize(dirty), dirty);

      // set the same hook
      DOMPurify.addHook(entryPoint, hookFunction);
      assert.equal(DOMPurify.sanitize(dirty), expected);

      // Teardown
      DOMPurify.removeHooks(entryPoint);
    });

    // -------------------------------------------------------------------
    // The allowlists are handed to the uponSanitize* hooks by reference (as
    // data.allowedTags / data.allowedAttributes), so a hook that widens them
    // - the documented in-call widening pattern - used to mutate the shared,
    // module-level set: the widening leaked into every later sanitize() call.
    // The guard clones the sets per walk, on both config paths (the per-call
    // path and the persistent setConfig() path). (GHSA-cmwh-pvxp-8882)
    // -------------------------------------------------------------------

    QUnit.test(
      'default config: attribute hook does not poison later calls',
      function (assert) {
        DOMPurify.addHook('uponSanitizeAttribute', function (node, data) {
          if (node.getAttribute && node.getAttribute('data-trusted') === '1') {
            data.allowedAttributes['onerror'] = true;
          }
        });

        try {
          // A trusted element widens onerror for its own call.
          assert.ok(
            DOMPurify.sanitize(
              '<img data-trusted="1" src="x" onerror="ok()">'
            ).indexOf('onerror') !== -1,
            'in-call widening works for the trusted element'
          );

          // A later untrusted call must NOT inherit the widened attribute.
          assert.equal(
            DOMPurify.sanitize('<img src="x" onerror="alert(1)">'),
            '<img src="x">',
            'untrusted call after trusted render strips onerror'
          );

          // Repeated calls must stay clean (no accumulated clone state).
          for (var i = 0; i < 5; i++) {
            assert.equal(
              DOMPurify.sanitize('<img src="x" onerror="alert(' + i + ')">'),
              '<img src="x">',
              'repeated untrusted call ' + i + ' stays clean'
            );
          }
        } finally {
          DOMPurify.removeHooks('uponSanitizeAttribute');
        }
      }
    );

    QUnit.test(
      'default config: element hook does not poison later calls',
      function (assert) {
        DOMPurify.addHook('uponSanitizeElement', function (node, data) {
          if (
            node.getAttribute &&
            node.getAttribute('data-trusted') === '1' &&
            data.allowedTags
          ) {
            data.allowedTags['bogus-tag'] = true;
          }
        });

        try {
          assert.ok(
            DOMPurify.sanitize(
              '<div data-trusted="1"><bogus-tag>abc</bogus-tag></div>'
            ).indexOf('bogus-tag') !== -1,
            'in-call widening works for the trusted element'
          );

          assert.equal(
            DOMPurify.sanitize('<bogus-tag>abc</bogus-tag>'),
            'abc',
            'untrusted <bogus-tag> not allowed after trusted render'
          );
        } finally {
          DOMPurify.removeHooks('uponSanitizeElement');
        }
      }
    );

    // -------------------------------------------------------------------
    // Persistent-config path (setConfig). sanitize() skips _parseConfig once
    // setConfig() has run, so the sets are not re-derived per call: a hook
    // write to data.allowedAttributes would mutate the allowlist for the
    // instance lifetime, across calls and elements. The guard is applied on
    // every sanitize() call for both config paths. (GHSA-cmwh-pvxp-8882)
    // -------------------------------------------------------------------

    QUnit.test(
      'setConfig: attribute hook does not poison later calls',
      function (assert) {
        DOMPurify.setConfig({ ALLOWED_TAGS: ['img'], ALLOWED_ATTR: ['src'] });
        DOMPurify.addHook('uponSanitizeAttribute', function (node, data) {
          if (node.getAttribute && node.getAttribute('data-trusted') === '1') {
            data.allowedAttributes['onerror'] = true;
          }
        });

        try {
          // A trusted element widens onerror for its own call.
          assert.ok(
            DOMPurify.sanitize(
              '<img data-trusted="1" src="x" onerror="ok()">'
            ).indexOf('onerror') !== -1,
            'in-call widening works for the trusted element under setConfig'
          );

          // A later untrusted call must NOT inherit the widened attribute.
          assert.equal(
            DOMPurify.sanitize('<img src="x" onerror="alert(1)">'),
            '<img src="x">',
            'untrusted call after trusted render strips onerror'
          );

          // Repeated calls must stay clean (no accumulated clone state).
          for (var i = 0; i < 5; i++) {
            assert.equal(
              DOMPurify.sanitize('<img src="x" onerror="alert(' + i + ')">'),
              '<img src="x">',
              'repeated untrusted call ' + i + ' stays clean'
            );
          }
        } finally {
          DOMPurify.removeHooks('uponSanitizeAttribute');
          DOMPurify.clearConfig();
        }
      }
    );

    QUnit.test(
      'setConfig: element hook does not poison later calls',
      function (assert) {
        DOMPurify.setConfig({ ALLOWED_TAGS: ['span'], ALLOWED_ATTR: [] });
        DOMPurify.addHook('uponSanitizeElement', function (node, data) {
          if (
            node.getAttribute &&
            node.getAttribute('data-trusted') === '1' &&
            data.allowedTags
          ) {
            data.allowedTags['img'] = true;
          }
        });

        try {
          DOMPurify.sanitize('<span data-trusted="1"><img src="x"></span>');

          assert.equal(
            DOMPurify.sanitize('<img src="x" onerror="alert(1)">'),
            '',
            'untrusted <img> not allowed after trusted render under setConfig'
          );
        } finally {
          DOMPurify.removeHooks('uponSanitizeElement');
          DOMPurify.clearConfig();
        }
      }
    );

    QUnit.test(
      'setConfig: clearConfig restores a clean state',
      function (assert) {
        DOMPurify.setConfig({ ALLOWED_TAGS: ['img'], ALLOWED_ATTR: ['src'] });
        DOMPurify.addHook('uponSanitizeAttribute', function (node, data) {
          if (node.getAttribute && node.getAttribute('data-trusted') === '1') {
            data.allowedAttributes['onerror'] = true;
          }
        });

        try {
          DOMPurify.sanitize('<img data-trusted="1" src="x" onerror="ok()">');

          DOMPurify.clearConfig();

          assert.equal(
            DOMPurify.sanitize('<img src="x" onerror="alert(1)">'),
            '<img src="x">',
            'default-cfg call after clearConfig strips onerror'
          );
        } finally {
          DOMPurify.removeHooks('uponSanitizeAttribute');
          DOMPurify.clearConfig();
        }
      }
    );

    QUnit.test(
      'reused config object: attribute hook does not poison later calls',
      function (assert) {
        // The parsed config is handed to hooks as their third argument, so a
        // caller can pass it straight back into sanitize(); _parseConfig then
        // returns early without re-deriving the sets.
        var seenConfig = null;
        DOMPurify.addHook('uponSanitizeAttribute', function (node, data, cfg) {
          seenConfig = cfg;
          if (node.getAttribute && node.getAttribute('data-trusted') === '1') {
            data.allowedAttributes['onerror'] = true;
          }
        });

        try {
          var config = { ALLOWED_TAGS: ['img'], ALLOWED_ATTR: ['src'] };
          assert.ok(
            DOMPurify.sanitize(
              '<img data-trusted="1" src="x" onerror="ok()">',
              config
            ).indexOf('onerror') !== -1,
            'in-call widening works for the trusted element'
          );
          assert.ok(seenConfig, 'the hook received the parsed config object');

          assert.equal(
            DOMPurify.sanitize('<img src="x" onerror="alert(1)">', seenConfig),
            '<img src="x">',
            'reusing the parsed config object does not inherit onerror'
          );
        } finally {
          DOMPurify.removeHooks('uponSanitizeAttribute');
        }
      }
    );

    // -------------------------------------------------------------------
    // The hooks registry is a plain object, so an unknown entry point such
    // as '__proto__' used to resolve off the prototype chain and arrayPush
    // then wrote to Object.prototype. (GHSA-cmwh-pvxp-8882)
    // -------------------------------------------------------------------

    QUnit.test(
      'addHook ignores unknown entry points and does not pollute Object.prototype',
      function (assert) {
        var hookFunction = function () {};

        try {
          DOMPurify.addHook('__proto__', hookFunction);

          assert.equal(
            {}.length,
            undefined,
            'Object.prototype.length was not created'
          );
          assert.equal({}[0], undefined, 'Object.prototype[0] was not created');
          assert.equal([].length, 0, 'Array.prototype was not affected');

          // Unknown entry points are ignored, not thrown on.
          DOMPurify.addHook('constructor', hookFunction);
          DOMPurify.addHook('notAHook', hookFunction);
          assert.equal(
            DOMPurify.removeHook('__proto__'),
            undefined,
            'removeHook on an unknown entry point returns undefined'
          );
          DOMPurify.removeHooks('__proto__');
          assert.equal(
            {}.length,
            undefined,
            'Object.prototype still untouched after removeHook(s)'
          );

          // Real hooks keep working.
          DOMPurify.addHook('afterSanitizeAttributes', function (node) {
            if (node.setAttribute) {
              node.setAttribute('class', 'world');
            }
          });
          assert.equal(
            DOMPurify.sanitize('<div class="hello"></div>'),
            '<div class="world"></div>',
            'known entry points are still registered'
          );
        } finally {
          DOMPurify.removeHooks('afterSanitizeAttributes');
          delete Object.prototype[0];
          delete Object.prototype.length;
        }
      }
    );

    // -------------------------------------------------------------------
    // GHSA-r47g-fvhr-h676 - parent-less clobbered IN_PLACE root retains
    // attacker-controlled attributes. _forceRemove cannot detach a root
    // without a parent and _sanitizeAttributes early-returns on
    // _isClobbered, so any event-handler attribute on the root survived.
    // sanitize() must instead throw on a clobbered IN_PLACE root, the same
    // way it throws on a forbidden root tag.
    // -------------------------------------------------------------------

    /* Returns true when this engine implements HTMLFormElement
     * [LegacyOverrideBuiltIns] named-property clobbering for forms created
     * by `ownerDocument` (real browsers do; jsdom does not). */
    function _formClobberingSupported(ownerDocument) {
      try {
        var probeForm = ownerDocument.createElement('form');
        var probeInput = ownerDocument.createElement('input');
        probeInput.setAttribute('name', 'attributes');
        probeForm.appendChild(probeInput);
        return probeForm.attributes === probeInput;
      } catch (_) {
        return false;
      }
    }

    /* Names covered by _isClobbered's checklist. */
    var _clobberNames = [
      'attributes',
      'nodeName',
      'textContent',
      'removeChild',
      'removeAttribute',
      'setAttribute',
      'namespaceURI',
      'insertBefore',
      'hasChildNodes',
    ];

    QUnit.test(
      'IN_PLACE: parent-less clobbered form root throws instead of returning the root with onmouseover intact (GHSA-r47g-fvhr-h676)',
      function (assert) {
        if (!_formClobberingSupported(document)) {
          assert.ok(true, 'SKIP: no form clobbering in this engine');
          return;
        }

        _clobberNames.forEach(function (name) {
          var root = document.createElement('form');
          root.setAttribute('onmouseover', 'alert(1)');
          var clobber = document.createElement('input');
          clobber.setAttribute('name', name);
          root.appendChild(clobber);

          assert.throws(
            function () {
              DOMPurify.sanitize(root, { IN_PLACE: true });
            },
            /clobbered|forbidden/i,
            'IN_PLACE must refuse a root clobbered by name="' + name + '"'
          );
        });
      }
    );

    QUnit.test(
      'IN_PLACE: a parented clobbered form is still removed without throwing (GHSA-r47g-fvhr-h676)',
      function (assert) {
        if (!_formClobberingSupported(document)) {
          assert.ok(true, 'SKIP: no form clobbering in this engine');
          return;
        }

        var wrapper = document.createElement('div');
        var form = document.createElement('form');
        form.setAttribute('onmouseover', 'alert(1)');
        var clobber = document.createElement('input');
        clobber.setAttribute('name', 'attributes');
        form.appendChild(clobber);
        wrapper.appendChild(form);

        var clean = DOMPurify.sanitize(wrapper, { IN_PLACE: true });

        assert.equal(clean, wrapper, 'the wrapper root is returned');
        assert.equal(
          wrapper.getElementsByTagName('form').length,
          0,
          'parented clobbered form is removed by the iterator-driven path'
        );
        assert.notOk(
          /onmouseover/i.test(wrapper.innerHTML),
          'no handler survived: ' + wrapper.innerHTML
        );
      }
    );

    QUnit.test(
      'IN_PLACE: an unclobbered form root is still accepted (GHSA-r47g-fvhr-h676)',
      function (assert) {
        var root = document.createElement('form');
        root.setAttribute('onmouseover', 'alert(1)');
        root.setAttribute('class', 'kept');
        root.appendChild(document.createElement('input'));

        var clean = DOMPurify.sanitize(root, { IN_PLACE: true });

        assert.equal(clean, root, 'the root is returned');
        assert.notOk(root.hasAttribute('onmouseover'), 'handler is removed');
        assert.equal(root.getAttribute('class'), 'kept', 'safe attr is kept');
        assert.equal(
          root.getElementsByTagName('input').length,
          1,
          'safe child is kept'
        );
      }
    );

    // -------------------------------------------------------------------
    // GHSA-hpcv-96wg-7vj8 - cross-realm IN_PLACE sanitization. Nodes
    // created in another same-origin realm (e.g. an iframe's document)
    // pass the realm-agnostic _isNode check, but several downstream
    // security decisions used `instanceof` against the parent realm's
    // constructors (HTMLFormElement, NamedNodeMap, DocumentFragment,
    // Element). Each check short-circuited to false for foreign-realm
    // nodes and the matching sanitization branch was skipped: form
    // clobbering went undetected, <template>.content was never walked and
    // the namespace check was bypassed. (DOMPurify 2.x has no attached-
    // shadow-root pass, so the advisory's shadow-root variant has no 2.x
    // counterpart.)
    // -------------------------------------------------------------------

    /* Runs `callback(foreignDocument)` against the document of a fresh
     * same-origin iframe, i.e. a document whose nodes belong to a different
     * realm than the DOMPurify instance under test. Returns false (so the
     * caller can skip) when the environment cannot provide one. Exceptions
     * thrown by the callback are not swallowed. */
    function _withForeignRealmDocument(callback) {
      var iframe = null;
      var foreignDocument = null;

      try {
        if (document.body) {
          iframe = document.createElement('iframe');
          document.body.appendChild(iframe);
          foreignDocument = iframe.contentDocument;
        }
      } catch (_) {
        foreignDocument = null;
      }

      if (
        !foreignDocument ||
        typeof foreignDocument.createElement !== 'function' ||
        /* The document must really belong to another realm, otherwise the
           tests would not exercise the cross-realm code paths. */
        foreignDocument.createElement('div') instanceof window.Element
      ) {
        if (iframe && iframe.parentNode) {
          iframe.parentNode.removeChild(iframe);
        }

        return false;
      }

      try {
        callback(foreignDocument);
      } finally {
        if (iframe.parentNode) {
          iframe.parentNode.removeChild(iframe);
        }
      }

      return true;
    }

    QUnit.test(
      'IN_PLACE: cross-realm clobbered form root is refused (GHSA-hpcv-96wg-7vj8)',
      function (assert) {
        var ran = _withForeignRealmDocument(function (foreignDocument) {
          if (!_formClobberingSupported(foreignDocument)) {
            assert.ok(
              true,
              'SKIP: foreign realm does not implement HTMLFormElement ' +
                '[LegacyOverrideBuiltIns]; the bypass is not reproducible here'
            );
            return;
          }

          _clobberNames.forEach(function (name) {
            var form = foreignDocument.createElement('form');
            form.setAttribute('onmouseover', 'alert(1)');
            var clobber = foreignDocument.createElement('input');
            clobber.setAttribute('name', name);
            form.appendChild(clobber);

            // Before the fix `form instanceof HTMLFormElement` was false for
            // the foreign-realm form, so it was never flagged as clobbered,
            // the attribute walk read the clobbered .attributes and the
            // onmouseover handler on the root survived.
            assert.throws(
              function () {
                DOMPurify.sanitize(form, { IN_PLACE: true });
              },
              /clobbered|forbidden/i,
              'foreign-realm root clobbered by name="' +
                name +
                '" must not be handed back'
            );
          });
        });

        if (!ran) {
          assert.ok(true, 'SKIP: cannot construct a foreign-realm document');
        }
      }
    );

    QUnit.test(
      'IN_PLACE: cross-realm clobbered form below the root is removed (GHSA-hpcv-96wg-7vj8)',
      function (assert) {
        var ran = _withForeignRealmDocument(function (foreignDocument) {
          if (!_formClobberingSupported(foreignDocument)) {
            assert.ok(
              true,
              'SKIP: foreign realm does not implement HTMLFormElement ' +
                '[LegacyOverrideBuiltIns]; the bypass is not reproducible here'
            );
            return;
          }

          _clobberNames.forEach(function (name) {
            var wrapper = foreignDocument.createElement('div');
            var form = foreignDocument.createElement('form');
            form.setAttribute('onmouseover', 'alert(1)');
            form.setAttribute('action', 'javascript:alert(2)');
            var clobber = foreignDocument.createElement('input');
            clobber.setAttribute('name', name);
            form.appendChild(clobber);
            wrapper.appendChild(form);

            DOMPurify.sanitize(wrapper, { IN_PLACE: true });

            assert.equal(
              wrapper.getElementsByTagName('form').length,
              0,
              'foreign-realm form clobbered by name="' +
                name +
                '" must be removed'
            );
            assert.notOk(
              /onmouseover|javascript:/i.test(wrapper.innerHTML),
              'no handler survived: ' + wrapper.innerHTML
            );
          });
        });

        if (!ran) {
          assert.ok(true, 'SKIP: cannot construct a foreign-realm document');
        }
      }
    );

    QUnit.test(
      'IN_PLACE: cross-realm unclobbered form is sanitized, not refused (GHSA-hpcv-96wg-7vj8)',
      function (assert) {
        var ran = _withForeignRealmDocument(function (foreignDocument) {
          // Guards against over-flagging: the realm-independent
          // .attributes probe must accept a clean foreign-realm form.
          var form = foreignDocument.createElement('form');
          form.setAttribute('onmouseover', 'alert(1)');
          form.setAttribute('class', 'kept');
          form.appendChild(foreignDocument.createElement('input'));

          var clean = DOMPurify.sanitize(form, { IN_PLACE: true });

          assert.equal(clean, form, 'the root is returned');
          assert.notOk(form.hasAttribute('onmouseover'), 'handler removed');
          assert.equal(form.getAttribute('class'), 'kept', 'safe attr kept');
          assert.equal(
            form.getElementsByTagName('input').length,
            1,
            'safe child is kept'
          );
        });

        if (!ran) {
          assert.ok(true, 'SKIP: cannot construct a foreign-realm document');
        }
      }
    );

    QUnit.test(
      'IN_PLACE: cross-realm <template>.content is walked and sanitized (GHSA-hpcv-96wg-7vj8)',
      function (assert) {
        var ran = _withForeignRealmDocument(function (foreignDocument) {
          var wrapper = foreignDocument.createElement('div');
          var template = foreignDocument.createElement('template');
          if (!template.content) {
            assert.ok(true, 'SKIP: <template> is not supported here');
            return;
          }

          // The nested <template> covers the deep-template recursion in
          // _sanitizeShadowDOM, the outer one the main iterator.
          template.innerHTML =
            '<img src="x" onerror="alert(1)">' +
            '<template><img src="y" onerror="alert(2)"></template>';
          wrapper.appendChild(template);

          // Before the fix `template.content instanceof DocumentFragment`
          // was false for the foreign-realm fragment, so its contents were
          // never walked and the onerror handlers survived.
          DOMPurify.sanitize(wrapper, { IN_PLACE: true });

          var img = template.content.querySelector('img');
          assert.ok(img, 'template content was reached');
          assert.equal(
            img && img.getAttribute('onerror'),
            null,
            'onerror inside foreign-realm <template> must be stripped'
          );

          var inner = template.content.querySelector('template');
          var innerImg = inner && inner.content.querySelector('img');
          assert.ok(innerImg, 'nested template content was reached');
          assert.equal(
            innerImg && innerImg.getAttribute('onerror'),
            null,
            'onerror inside nested foreign-realm <template> must be stripped'
          );
        });

        if (!ran) {
          assert.ok(true, 'SKIP: cannot construct a foreign-realm document');
        }
      }
    );

    QUnit.test(
      'IN_PLACE: cross-realm element in a forbidden namespace is removed (GHSA-hpcv-96wg-7vj8)',
      function (assert) {
        var build = function (ownerDocument) {
          var wrapper = ownerDocument.createElement('div');
          // Allowed tag names in namespaces _checkValidNamespace rejects: an
          // unknown namespace, and an SVG element other than <svg> directly
          // below an HTML element.
          var bogus = ownerDocument.createElementNS(
            'urn:example:not-allowed',
            'div'
          );
          bogus.textContent = 'bogus';
          wrapper.appendChild(bogus);
          wrapper.appendChild(
            ownerDocument.createElementNS('http://www.w3.org/2000/svg', 'a')
          );
          return wrapper;
        };

        // Same-realm control: the namespace check removes both elements.
        var sameRealm = build(document);
        DOMPurify.sanitize(sameRealm, { IN_PLACE: true });
        assert.equal(sameRealm.innerHTML, '', 'same-realm control is cleaned');

        var ran = _withForeignRealmDocument(function (foreignDocument) {
          // Before the fix _checkValidNamespace was gated behind
          // `currentNode instanceof Element` (parent realm), so both
          // elements slipped past the namespace check.
          var wrapper = build(foreignDocument);
          DOMPurify.sanitize(wrapper, { IN_PLACE: true });

          assert.equal(
            wrapper.getElementsByTagNameNS('urn:example:not-allowed', '*')
              .length,
            0,
            'foreign-realm element in an unknown namespace must be removed'
          );
          assert.equal(
            wrapper.getElementsByTagNameNS('http://www.w3.org/2000/svg', '*')
              .length,
            0,
            'foreign-realm SVG <a> directly below HTML must be removed'
          );
          assert.equal(wrapper.innerHTML, '', 'foreign-realm wrapper cleaned');
        });

        if (!ran) {
          assert.ok(true, 'SKIP: cannot construct a foreign-realm document');
        }
      }
    );

    // ---------------------------------------------------------------------------
    // NodeType clobbering probe (hardening shipped with GHSA-76mc-f452-cxcm).
    //
    // A <form> holding <input name="nodeType"> shadows Node.prototype.nodeType
    // on direct reads ([LegacyOverrideBuiltIns]). _isClobbered compares the
    // direct read against the cached prototype getter, so such a form is
    // treated as clobbered: removed when parented, refused as an IN_PLACE root.
    // ---------------------------------------------------------------------------

    /* Returns true when a form created by `ownerDocument` lets a named child
     * shadow Node.prototype.nodeType (real browsers do; jsdom does not). */
    function _nodeTypeClobberingSupported(ownerDocument) {
      if (!_formClobberingSupported(ownerDocument)) {
        return false;
      }

      try {
        var probeForm = ownerDocument.createElement('form');
        var probeInput = ownerDocument.createElement('input');
        probeInput.setAttribute('name', 'nodeType');
        probeForm.appendChild(probeInput);
        return probeForm.nodeType === probeInput;
      } catch (_) {
        return false;
      }
    }

    QUnit.test(
      'form clobbered via name="nodeType" is removed (GHSA-76mc-f452-cxcm)',
      function (assert) {
        if (!_nodeTypeClobberingSupported(document)) {
          assert.ok(true, 'SKIP: no nodeType clobbering in this engine');
          return;
        }

        // Before the probe the form was not flagged as clobbered and was kept
        // (only the clobbering name attribute was dropped by SANITIZE_DOM).
        assert.equal(
          DOMPurify.sanitize(
            '<div><form><input name="nodeType"><b>x</b></form></div>'
          ),
          '<div></div>',
          'nodeType-clobbered form is removed together with its content'
        );

        // An unclobbered form is still kept.
        assert.equal(
          DOMPurify.sanitize('<div><form><input name="foo"></form></div>'),
          '<div><form><input name="foo"></form></div>',
          'unclobbered form is kept'
        );
      }
    );

    QUnit.test(
      'IN_PLACE: form root clobbered via name="nodeType" is refused (GHSA-76mc-f452-cxcm)',
      function (assert) {
        if (!_nodeTypeClobberingSupported(document)) {
          assert.ok(true, 'SKIP: no nodeType clobbering in this engine');
          return;
        }

        var root = document.createElement('form');
        root.setAttribute('onmouseover', 'alert(1)');
        var clobber = document.createElement('input');
        clobber.setAttribute('name', 'nodeType');
        root.appendChild(clobber);

        assert.throws(
          function () {
            DOMPurify.sanitize(root, { IN_PLACE: true });
          },
          /clobbered|forbidden/i,
          'IN_PLACE must refuse a root clobbered by name="nodeType"'
        );
      }
    );

    // ---------------------------------------------------------------------------
    // Hook-driven allowlist pollution (GHSA-76mc-f452-cxcm).
    //
    // The data.allowedTags / data.allowedAttributes fields passed to
    // uponSanitizeElement / uponSanitizeAttribute hooks are direct references
    // to the live ALLOWED_TAGS / ALLOWED_ATTR sets. When no explicit
    // cfg.ALLOWED_TAGS was supplied, that live set WAS the module-level
    // DEFAULT_ALLOWED_TAGS constant. A hook that wrote
    //     data.allowedTags['script'] = true
    // therefore wrote permanently into the default constant. Subsequent
    // sanitize calls - even after removeAllHooks() and clearConfig() -
    // inherited the widened defaults until the entire DOMPurify instance
    // was recreated.
    //
    // Fix: when any uponSanitize* hook is registered, the allowlist sets are
    // cloned for the duration of the call. The hook then mutates the clone,
    // preserving the documented in-call widening behavior (the test
    // "ensure that a hook can add allowed tags / attributes on the fly"
    // continues to pass), while the next default-cfg call rebinds to the
    // untouched default.
    // ---------------------------------------------------------------------------

    QUnit.module(
      'Hook-driven allowlist pollution (GHSA-76mc-f452-cxcm)',
      function (hooks) {
        var purify;
        hooks.beforeEach(function () {
          // Fresh instance per test - the bug under test IS cross-call
          // pollution, so test isolation requires per-test instances.
          purify = DOMPurify(window);
        });
        hooks.afterEach(function () {
          purify.removeAllHooks();
          purify.clearConfig();
        });

        QUnit.test(
          'baseline: <script> and onclick are stripped under default config',
          function (assert) {
            assert.equal(
              purify.sanitize('<svg><script>alert(1)</script></svg>'),
              '<svg></svg>',
              'fresh default sanitize strips <script>'
            );
            assert.equal(
              purify.sanitize('<a onclick="alert(1)">x</a>'),
              '<a>x</a>',
              'fresh default sanitize strips onclick'
            );
          }
        );

        QUnit.test(
          'in-call widening via hook still works (documented behavior preserved)',
          function (assert) {
            // This mirrors the test "ensure that a hook can add allowed
            // tags / attributes on the fly" and asserts that the pollution
            // fix did not break the documented hook-widening API. The fix
            // preserves in-call widening by handing the hook a clone of the
            // default; the clone is mutated and used for the rest of the
            // iteration.
            purify.addHook('uponSanitizeElement', function (node, data) {
              if (data.tagName === 'is-custom') {
                data.allowedTags['is-custom'] = true;
              }
            });
            purify.addHook('uponSanitizeAttribute', function (node, data) {
              if (data.attrName === 'super-custom') {
                data.allowedAttributes['super-custom'] = true;
              }
            });

            var input =
              '<p>HE<is-custom super-custom="test">LLO</is-custom></p>';
            assert.equal(
              purify.sanitize(input),
              input,
              'guarded hook widens allowlist for matching element in-call'
            );
          }
        );

        QUnit.test(
          'unguarded element hook does not poison subsequent default-config calls',
          function (assert) {
            purify.addHook('uponSanitizeElement', function (node, data) {
              // The "leaky" pattern: unconditionally widen.
              data.allowedTags['script'] = true;
            });

            // First call: hook is active. In-call widening works (mirrors
            // the documented behavior), so script survives.
            assert.equal(
              purify.sanitize('<svg><script>1</script></svg>'),
              '<svg><script>1</script></svg>',
              'in-call widening still works while hook is registered'
            );

            purify.removeAllHooks();
            purify.clearConfig();

            // Second call after hook removal: the bug. Pre-fix, the module
            // default has been polluted and <script> still passes. Post-fix,
            // the default was never touched (only the per-call clone was)
            // and <script> is correctly stripped.
            assert.equal(
              purify.sanitize('<svg><script>alert(1)</script></svg>'),
              '<svg></svg>',
              'default sanitize after element-hook removal strips <script>'
            );
          }
        );

        QUnit.test(
          'unguarded attribute hook does not poison subsequent default-config calls',
          function (assert) {
            purify.addHook('uponSanitizeAttribute', function (node, data) {
              data.allowedAttributes['onclick'] = true;
            });

            // In-call widening works.
            assert.ok(
              purify
                .sanitize('<a onclick="alert(1)">x</a>')
                .indexOf('onclick') !== -1,
              'in-call widening still works for attribute hook'
            );

            purify.removeAllHooks();
            purify.clearConfig();

            assert.equal(
              purify.sanitize('<a onclick="alert(1)">x</a>'),
              '<a>x</a>',
              'default sanitize after attr-hook removal strips onclick'
            );
          }
        );

        QUnit.test(
          'pollution does not cross instance boundaries',
          function (assert) {
            // Pollute the first instance.
            purify.addHook('uponSanitizeElement', function (node, data) {
              data.allowedTags['script'] = true;
            });
            purify.sanitize('<svg><script>alert(1)</script></svg>');

            // A separately-constructed instance must not inherit the
            // (now-fixed-or-not) state of the first instance.
            var freshInstance = DOMPurify(window);
            assert.equal(
              freshInstance.sanitize('<svg><script>alert(1)</script></svg>'),
              '<svg></svg>',
              'fresh DOMPurify instance must not inherit poisoned defaults'
            );
          }
        );

        QUnit.test(
          'read-only hook does not poison defaults',
          function (assert) {
            // Pure-read access to data.allowedTags is the safest hook
            // pattern and must continue to work. The pre-clone is harmless
            // here - the hook reads from a clone, then the clone is
            // discarded at call end.
            var sawScriptKey;
            purify.addHook('uponSanitizeElement', function (node, data) {
              if (sawScriptKey === undefined) {
                sawScriptKey = 'script' in data.allowedTags;
              }
            });

            purify.sanitize('<div><span>hi</span></div>');

            assert.strictEqual(
              sawScriptKey,
              false,
              'hook sees default allowlist with script NOT included'
            );

            purify.removeAllHooks();
            purify.clearConfig();

            assert.equal(
              purify.sanitize('<svg><script>alert(1)</script></svg>'),
              '<svg></svg>',
              'read-only hook does not poison defaults'
            );
          }
        );

        QUnit.test(
          'multiple polluting calls do not accumulate state in defaults',
          function (assert) {
            // Stress: many calls with a polluting hook, then check recovery.
            // Each call gets a fresh clone; the clones are discarded at call
            // end; module defaults stay clean.
            purify.addHook('uponSanitizeElement', function (node, data) {
              data.allowedTags['script'] = true;
              data.allowedTags['iframe'] = true;
              data.allowedTags['object'] = true;
            });

            for (var i = 0; i < 10; i++) {
              purify.sanitize('<div></div>');
            }

            purify.removeAllHooks();
            purify.clearConfig();

            assert.equal(
              purify.sanitize('<svg><script>1</script></svg>'),
              '<svg></svg>',
              'script still stripped after 10 polluting calls'
            );
            assert.equal(
              purify.sanitize('<iframe src="x"></iframe>'),
              '',
              'iframe still stripped after 10 polluting calls'
            );
            assert.equal(
              purify.sanitize('<object data="x"></object>'),
              '',
              'object still stripped after 10 polluting calls'
            );
          }
        );

        QUnit.test(
          'explicit cfg.ALLOWED_TAGS path is unaffected by hook mutation in other calls',
          function (assert) {
            // When cfg.ALLOWED_TAGS is supplied, ALLOWED_TAGS is already a
            // per-call fresh object (built via addToSet({}, ...)), not the
            // module default. Hooks mutating it can't pollute the default
            // even pre-fix. Asserting this explicitly catches a hypothetical
            // over-correction that breaks the explicit-cfg path.
            purify.addHook('uponSanitizeElement', function (node, data) {
              data.allowedTags['script'] = true;
            });

            // First call: explicit restrictive cfg, hook widens, script
            // survives in-call.
            var withCfg = purify.sanitize(
              '<svg><script>alert(1)</script></svg>',
              { ALLOWED_TAGS: ['svg'] }
            );
            assert.ok(
              withCfg.indexOf('<script>') !== -1,
              'explicit-cfg call respects in-call hook widening: ' + withCfg
            );

            purify.removeAllHooks();
            purify.clearConfig();

            // Default call afterwards must still be clean.
            assert.equal(
              purify.sanitize('<svg><script>alert(1)</script></svg>'),
              '<svg></svg>',
              'default-cfg call after explicit-cfg+hook is unaffected'
            );
          }
        );
      }
    );

    // ---------------------------------------------------------------------------
    // Attached shadow root inside <template>.content (CVE-2026-49978,
    // GHSA-rp9w-3fw7-7cwq).
    //
    // <template>.content is walked by _sanitizeShadowDOM, whose node iterator
    // does not enter shadow trees. A shadow root attached to an element inside
    // the template content was therefore reached by no walk at all, and its
    // payload survived sanitization - and, for clonable shadow roots, the
    // stamping of the template into the live document. The fix inspects the
    // shadowRoot of every element _sanitizeShadowDOM iterates and walks it.
    //
    // This version has no separate pass over shadow roots attached to the
    // IN_PLACE root's own (non-template) tree, so the shadow-root-first shapes
    // of the upstream tests are rooted inside a <template> here.
    // ---------------------------------------------------------------------------

    QUnit.module(
      'IN_PLACE: shadow root inside template.content (CVE-2026-49978)',
      function (hooks) {
        var purify;
        hooks.beforeEach(function () {
          purify = DOMPurify(window);
        });
        hooks.afterEach(function () {
          purify.removeAllHooks();
          purify.clearConfig();
        });

        /* Returns a fresh <div> with an open shadow root, or null when the
         * engine has no Shadow DOM. */
        function _createShadowHost(clonable) {
          var host = document.createElement('div');
          try {
            if (clonable) {
              host.attachShadow({ mode: 'open', clonable: true });
            } else {
              host.attachShadow({ mode: 'open' });
            }
          } catch (_) {
            return null;
          }

          return host.shadowRoot ? host : null;
        }

        /* Returns true when cloning a node also clones its clonable shadow
         * root - the stamping path the advisory describes. */
        function _clonableShadowRootSupported() {
          var probe = _createShadowHost(true);
          if (!probe) {
            return false;
          }

          try {
            return Boolean(probe.cloneNode(true).shadowRoot);
          } catch (_) {
            return false;
          }
        }

        QUnit.test(
          'shadow root inside template.content is sanitized in-place',
          function (assert) {
            var tpl = document.createElement('template');
            var host = _createShadowHost(false);
            if (!tpl.content || !host) {
              assert.ok(true, 'SKIP: template / attachShadow not supported');
              return;
            }

            tpl.content.appendChild(host);
            host.shadowRoot.innerHTML = '<img src=x onerror=alert(1)>';

            purify.sanitize(tpl, { IN_PLACE: true });

            // The shadow root's onerror attribute must be stripped.
            var shadowImg =
              tpl.content.firstChild &&
              tpl.content.firstChild.shadowRoot &&
              tpl.content.firstChild.shadowRoot.querySelector('img');
            if (shadowImg) {
              assert.equal(
                shadowImg.getAttribute('onerror'),
                null,
                'onerror inside shadow root inside template.content must be stripped'
              );
            } else {
              // The whole img may have been removed; also acceptable.
              assert.ok(
                true,
                '<img> removed entirely from shadow root inside template.content'
              );
            }
          }
        );

        QUnit.test(
          'clonable shadow root inside template.content does not survive stamping',
          function (assert) {
            if (!_clonableShadowRootSupported()) {
              assert.ok(
                true,
                'SKIP: clonable shadow roots not supported in this engine'
              );
              return;
            }

            var tpl = document.createElement('template');
            var host = _createShadowHost(true);
            tpl.content.appendChild(host);
            host.shadowRoot.innerHTML = '<img src=x onerror=alert(1)>';

            purify.sanitize(tpl, { IN_PLACE: true });

            // The realistic exploitation path: clone the (now-sanitized)
            // template content into the live document. The cloned shadow
            // tree must not carry the onerror.
            var clone = tpl.content.cloneNode(true);
            var clonedImg =
              clone.firstChild &&
              clone.firstChild.shadowRoot &&
              clone.firstChild.shadowRoot.querySelector('img');
            if (clonedImg) {
              assert.equal(
                clonedImg.getAttribute('onerror'),
                null,
                'onerror inside cloned-stamped shadow root must be stripped'
              );
            } else {
              assert.ok(true, '<img> removed entirely after stamping');
            }
          }
        );

        QUnit.test(
          'symmetric: <template> nested inside a shadow root inside template.content is walked',
          function (assert) {
            // The shadow-in-template variant the reporter mentions. A
            // <template> appearing inside a shadow root, with content
            // carrying an event handler, must have its content walked too.
            var tpl = document.createElement('template');
            var host = _createShadowHost(false);
            if (!tpl.content || !host) {
              assert.ok(true, 'SKIP: template / attachShadow not supported');
              return;
            }

            var inner = document.createElement('template');
            inner.innerHTML = '<img src=x onerror=alert(1)>';
            host.shadowRoot.appendChild(inner);
            tpl.content.appendChild(host);

            purify.sanitize(tpl, { IN_PLACE: true });

            var sr = tpl.content.firstChild && tpl.content.firstChild.shadowRoot;
            var img =
              sr &&
              sr.querySelector('template') &&
              sr.querySelector('template').content.querySelector('img');
            if (img) {
              assert.equal(
                img.getAttribute('onerror'),
                null,
                'onerror inside <template>.content inside shadow root must be stripped'
              );
            } else {
              assert.ok(true, '<img> removed entirely');
            }
          }
        );

        QUnit.test(
          'nested templates: outer.content > inner.content > shadow root',
          function (assert) {
            // Two <template> elements nested by content. The innermost
            // host inside the inner template's content carries the
            // malicious shadow root. Reaches the host only via repeated
            // recursion into template.content.
            var outer = document.createElement('template');
            var inner = document.createElement('template');
            var host = _createShadowHost(false);
            if (!outer.content || !host) {
              assert.ok(true, 'SKIP: template / attachShadow not supported');
              return;
            }

            inner.content.appendChild(host);
            outer.content.appendChild(inner);
            host.shadowRoot.innerHTML = '<img src=x onerror=alert(1)>';

            purify.sanitize(outer, { IN_PLACE: true });

            var sr =
              outer.content.firstChild &&
              outer.content.firstChild.content &&
              outer.content.firstChild.content.firstChild &&
              outer.content.firstChild.content.firstChild.shadowRoot;
            var img = sr && sr.querySelector('img');
            if (img) {
              assert.equal(
                img.getAttribute('onerror'),
                null,
                'onerror in shadow root inside nested template content must be stripped'
              );
            } else {
              assert.ok(true, '<img> removed entirely');
            }
          }
        );

        QUnit.test(
          'wrapper element > template > shadow root: walked via descent',
          function (assert) {
            // A regular <div> as the IN_PLACE root, containing a template,
            // whose content holds a shadow host. The main walk reaches the
            // template, recurses into template.content, and must walk the
            // host's shadow root.
            var root = document.createElement('div');
            var tpl = document.createElement('template');
            var host = _createShadowHost(false);
            if (!tpl.content || !host) {
              assert.ok(true, 'SKIP: template / attachShadow not supported');
              return;
            }

            tpl.content.appendChild(host);
            host.shadowRoot.innerHTML = '<img src=x onerror=alert(1)>';
            root.appendChild(tpl);

            purify.sanitize(root, { IN_PLACE: true });

            var sr =
              root.firstChild &&
              root.firstChild.content &&
              root.firstChild.content.firstChild &&
              root.firstChild.content.firstChild.shadowRoot;
            var img = sr && sr.querySelector('img');
            if (img) {
              assert.equal(
                img.getAttribute('onerror'),
                null,
                'onerror in shadow root inside template inside wrapper must be stripped'
              );
            } else {
              assert.ok(true, '<img> removed entirely');
            }
          }
        );

        QUnit.test(
          'shadow root > template > shadow root inside template.content: alternating descent',
          function (assert) {
            // Outer host with shadow root (itself inside template content),
            // whose shadow contains a <template>, whose content contains an
            // inner host with its own shadow root carrying the payload. The
            // walk has to alternate between shadow-root descent and
            // template-content recursion, reaching arbitrary depth.
            var tpl = document.createElement('template');
            var outerHost = _createShadowHost(false);
            if (!tpl.content || !outerHost) {
              assert.ok(true, 'SKIP: template / attachShadow not supported');
              return;
            }

            var innerTpl = document.createElement('template');
            var innerHost = _createShadowHost(false);
            innerTpl.content.appendChild(innerHost);
            outerHost.shadowRoot.appendChild(innerTpl);
            tpl.content.appendChild(outerHost);
            innerHost.shadowRoot.innerHTML = '<img src=x onerror=alert(1)>';

            purify.sanitize(tpl, { IN_PLACE: true });

            var outerSr =
              tpl.content.firstChild && tpl.content.firstChild.shadowRoot;
            var innerSr =
              outerSr &&
              outerSr.firstChild &&
              outerSr.firstChild.content &&
              outerSr.firstChild.content.firstChild &&
              outerSr.firstChild.content.firstChild.shadowRoot;
            var img = innerSr && innerSr.querySelector('img');
            if (img) {
              assert.equal(
                img.getAttribute('onerror'),
                null,
                'onerror in deep shadow > template > shadow chain must be stripped'
              );
            } else {
              assert.ok(true, '<img> removed entirely');
            }
          }
        );

        QUnit.test(
          'clonable shadow root in nested template survives stamping unscathed',
          function (assert) {
            // End-to-end version of the deeper-nesting case: clonable
            // shadow root inside nested template content, then stamp the
            // outer template into the live document. The cloned tree
            // must not carry the original onerror.
            if (!_clonableShadowRootSupported()) {
              assert.ok(true, 'SKIP: clonable shadow roots not supported');
              return;
            }

            var outer = document.createElement('template');
            var inner = document.createElement('template');
            var host = _createShadowHost(true);
            inner.content.appendChild(host);
            outer.content.appendChild(inner);
            host.shadowRoot.innerHTML = '<img src=x onerror=alert(1)>';

            purify.sanitize(outer, { IN_PLACE: true });

            // Stamp the outer template into the live document.
            var stamped = outer.content.cloneNode(true);
            var stampedSr =
              stamped.firstChild &&
              stamped.firstChild.content &&
              stamped.firstChild.content.firstChild &&
              stamped.firstChild.content.firstChild.shadowRoot;
            var stampedImg = stampedSr && stampedSr.querySelector('img');
            if (stampedImg) {
              assert.equal(
                stampedImg.getAttribute('onerror'),
                null,
                'stamped img onerror stripped after deep-nested sanitize'
              );
            } else {
              assert.ok(true, '<img> removed entirely after stamping');
            }
          }
        );

        QUnit.test(
          'DOM input: clonable shadow root inside template.content is sanitized in the RETURN_DOM copy',
          function (assert) {
            // Without IN_PLACE, DOM input is copied via importNode(), which
            // also clones clonable shadow roots inside template content. The
            // copy is walked through the same _sanitizeShadowDOM recursion.
            if (!_clonableShadowRootSupported()) {
              assert.ok(true, 'SKIP: clonable shadow roots not supported');
              return;
            }

            var tpl = document.createElement('template');
            var host = _createShadowHost(true);
            tpl.content.appendChild(host);
            host.shadowRoot.innerHTML =
              '<img src=x onerror=alert(1)><script>alert(2)</script><b>ok</b>';

            var body = purify.sanitize(tpl, { RETURN_DOM: true });

            var returnedTpl = body.querySelector('template');
            var sr =
              returnedTpl &&
              returnedTpl.content.firstChild &&
              returnedTpl.content.firstChild.shadowRoot;
            assert.ok(sr, 'shadow root was cloned into the returned tree');
            var img = sr && sr.querySelector('img');
            assert.equal(
              img && img.getAttribute('onerror'),
              null,
              'onerror inside cloned shadow root must be stripped'
            );
            assert.equal(
              sr && sr.querySelector('script'),
              null,
              '<script> inside cloned shadow root must be removed'
            );
            assert.ok(
              sr && sr.querySelector('b'),
              'safe content inside the shadow root is kept'
            );
          }
        );
      }
    );

    // ---------------------------------------------------------------------------
    // IN_PLACE trusts attacker-controlled nodeName (GHSA-x4vx-rjvf-j5p4).
    //
    // A live node handed to IN_PLACE sanitization by a lower-trust same-origin
    // context (an iframe, a popup, an adopted node) can carry an own `nodeName`
    // property shadowing Node.prototype.nodeName, e.g. a real <script> that
    // reports 'DIV'. _isClobbered only inspects <form> elements, so the spoofed
    // name decided the allow/forbid check and the script survived, executing
    // once the host inserted the sanitized subtree. The tag name is now read
    // through the cached Node.prototype.nodeName getter in the element check,
    // the attribute check and the IN_PLACE root pre-check.
    // ---------------------------------------------------------------------------

    QUnit.module(
      'IN_PLACE: spoofed nodeName (GHSA-x4vx-rjvf-j5p4)',
      function (hooks) {
        var purify;
        hooks.beforeEach(function () {
          purify = DOMPurify(window);
        });
        hooks.afterEach(function () {
          purify.removeAllHooks();
          purify.clearConfig();
          window.__x4vxFired = undefined;
        });

        /* Shadows Node.prototype.nodeName on this one node, as the advisory's
           PoC does: Object.defineProperty(script, 'nodeName', {value: 'DIV'}) */
        function spoofNodeName(node, name) {
          Object.defineProperty(node, 'nodeName', {
            configurable: true,
            value: name,
          });
          return node;
        }

        /* Inserts the sanitized subtree into the live document - the step
           at which a surviving <script> fires - and reports whether the
           payload ran. Engines that do not run scripts (jsdom) report false
           and rely on the structural assertions. */
        function payloadFiresOnInsert(node) {
          window.__x4vxFired = false;
          if (document.body) {
            document.body.appendChild(node);
            document.body.removeChild(node);
          }

          return window.__x4vxFired === true;
        }

        var payload = 'window.__x4vxFired = true;';

        QUnit.test(
          'IN_PLACE: <script> below the root reporting nodeName "DIV" is removed (GHSA-x4vx-rjvf-j5p4)',
          function (assert) {
            var wrapper = document.createElement('div');
            var script = document.createElement('script');
            script.textContent = payload;
            spoofNodeName(script, 'DIV');
            wrapper.appendChild(script);
            assert.equal(script.nodeName, 'DIV', 'precondition: spoofed');

            var clean = purify.sanitize(wrapper, { IN_PLACE: true });

            assert.equal(clean, wrapper, 'the root is returned');
            assert.equal(
              wrapper.getElementsByTagName('script').length,
              0,
              'spoofed <script> must be removed: ' + wrapper.innerHTML
            );
            assert.notOk(
              payloadFiresOnInsert(wrapper),
              'no script fires when the sanitized node is inserted'
            );
          }
        );

        QUnit.test(
          'IN_PLACE: forbidden elements spoofing an allowed nodeName are removed (GHSA-x4vx-rjvf-j5p4)',
          function (assert) {
            ['script', 'iframe', 'object', 'embed'].forEach(function (tag) {
              var wrapper = document.createElement('div');
              wrapper.appendChild(
                spoofNodeName(document.createElement(tag), 'SPAN')
              );

              purify.sanitize(wrapper, { IN_PLACE: true });

              assert.equal(
                wrapper.getElementsByTagName(tag).length,
                0,
                '<' + tag + '> reporting nodeName "SPAN" must be removed'
              );
            });
          }
        );

        QUnit.test(
          'IN_PLACE: flip-flopping nodeName getter cannot pass a <script> (GHSA-x4vx-rjvf-j5p4)',
          function (assert) {
            var wrapper = document.createElement('div');
            var script = document.createElement('script');
            script.textContent = payload;
            /* Alternates between the real and a spoofed name, so a check
               reading the property more than once sees different values */
            var reads = 0;
            Object.defineProperty(script, 'nodeName', {
              configurable: true,
              get: function () {
                reads++;
                return reads % 2 ? 'SCRIPT' : 'DIV';
              },
            });
            wrapper.appendChild(script);

            purify.sanitize(wrapper, { IN_PLACE: true });

            assert.equal(
              wrapper.getElementsByTagName('script').length,
              0,
              'flip-flopping <script> must be removed: ' + wrapper.innerHTML
            );
            assert.notOk(
              payloadFiresOnInsert(wrapper),
              'no script fires when the sanitized node is inserted'
            );
          }
        );

        QUnit.test(
          'IN_PLACE: parent-less <script> root reporting nodeName "DIV" is refused (GHSA-x4vx-rjvf-j5p4)',
          function (assert) {
            /* _forceRemove can not detach a root without a parent, so the
               root pre-check is the only gate for the root itself. */
            var root = document.createElement('script');
            root.textContent = payload;
            spoofNodeName(root, 'DIV');

            assert.throws(
              function () {
                purify.sanitize(root, { IN_PLACE: true });
              },
              /forbidden/i,
              'IN_PLACE must refuse a <script> root that reports "DIV"'
            );
          }
        );

        QUnit.test(
          'IN_PLACE: spoofed nodeName does not unlock tag-specific data: URIs (GHSA-x4vx-rjvf-j5p4)',
          function (assert) {
            /* data: URIs are only accepted for DATA_URI_TAGS such as <img>;
               an <a> reporting "IMG" must not get its data: href through */
            var wrapper = document.createElement('div');
            var link = document.createElement('a');
            link.setAttribute(
              'href',
              'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='
            );
            spoofNodeName(link, 'IMG');
            wrapper.appendChild(link);

            purify.sanitize(wrapper, { IN_PLACE: true });

            var a = wrapper.getElementsByTagName('a')[0];
            assert.ok(a, 'the <a> itself is allowed and kept');
            assert.notOk(
              a && a.hasAttribute('href'),
              'data: href on a spoofed <a> must be removed: ' + wrapper.innerHTML
            );
          }
        );

        QUnit.test(
          'IN_PLACE: cross-realm <script> reporting nodeName "DIV" is removed (GHSA-x4vx-rjvf-j5p4)',
          function (assert) {
            var ran = _withForeignRealmDocument(function (foreignDocument) {
              /* The advisory's flow: a same-origin iframe builds the
                 container and the spoofed script, the host sanitizes it in
                 place and inserts it into its own document. */
              var container = foreignDocument.createElement('div');
              var script = foreignDocument.createElement('script');
              script.textContent = payload;
              spoofNodeName(script, 'DIV');
              container.appendChild(script);

              purify.sanitize(container, { IN_PLACE: true });

              assert.equal(
                container.getElementsByTagName('script').length,
                0,
                'foreign-realm spoofed <script> must be removed: ' +
                  container.innerHTML
              );
              assert.notOk(
                payloadFiresOnInsert(container),
                'no script fires when the sanitized node is inserted'
              );
            });

            if (!ran) {
              assert.ok(true, 'SKIP: cannot construct a foreign-realm document');
            }
          }
        );
      }
    );

    // ---------------------------------------------------------------------------
    // IN_PLACE hook removal leaves a detached subtree executable
    // (CVE-2026-75838, GHSA-55q2-fjhq-7xh7).
    //
    // A hook that detaches a node via node.remove() (the documented removal
    // pattern) takes the subtree out of the tree before the walker reaches
    // its descendants, and hook-detached nodes are not recorded in
    // DOMPurify.removed. Without an inline neutralize right after the hook, a
    // descendant that was already loading keeps its queued on* handler and
    // fires in page scope after sanitize returns, even though the returned
    // tree is clean. onerror with no src: assert the attribute is gone rather
    // than waiting for a load. Covers both element hooks.
    //
    // A clobbered ownerDocument on a <form> IN_PLACE root made the iterator
    // construction throw before the walk, leaving every armed descendant of
    // the live root intact; the iterator now reads ownerDocument through the
    // cached Node.prototype getter.
    // ---------------------------------------------------------------------------

    QUnit.module(
      'IN_PLACE: hook-detached subtree is neutralized (CVE-2026-75838)',
      function (hooks) {
        var purify;
        hooks.beforeEach(function () {
          purify = DOMPurify(window);
        });
        hooks.afterEach(function () {
          purify.removeAllHooks();
          purify.clearConfig();
        });

        /* Detach a node the way the documented hook pattern does. */
        function _detach(node) {
          if (typeof node.remove === 'function') {
            node.remove();
          } else if (node.parentNode) {
            node.parentNode.removeChild(node);
          }
        }

        // Covers every per-node hook site that can detach the node: the
        // original before/upon element sites and the afterSanitizeElements /
        // beforeSanitizeAttributes / afterSanitizeAttributes sites the first
        // fix left open (the after* hooks are the documented place for
        // node.remove() policies) (CVE-2026-109345).
        [
          { hook: 'uponSanitizeElement', id: 'CVE-2026-75838' },
          { hook: 'beforeSanitizeElements', id: 'CVE-2026-75838' },
          { hook: 'afterSanitizeElements', id: 'CVE-2026-109345' },
          { hook: 'beforeSanitizeAttributes', id: 'CVE-2026-109345' },
          { hook: 'afterSanitizeAttributes', id: 'CVE-2026-109345' },
        ].forEach(function (site) {
          var hook = site.hook;

          QUnit.test(
            'IN_PLACE: ' +
              hook +
              ' node.remove() neutralizes the detached subtree (' +
              site.id +
              ')',
            function (assert) {
              var root = document.createElement('div');
              root.innerHTML =
                '<section><img id="tail" onerror="alert(1)"></section>' +
                '<div>safe</div>';
              var tail = root.querySelector('#tail');

              purify.addHook(hook, function (node) {
                if (node.nodeName === 'SECTION') {
                  _detach(node);
                }
              });

              var ret = purify.sanitize(root, { IN_PLACE: true });

              assert.equal(ret, root, 'returns the same in-place node');
              assert.notOk(
                ret.querySelector('section, #tail'),
                'detached subtree is absent from the returned tree'
              );
              assert.strictEqual(
                tail.getAttribute('onerror'),
                null,
                'on* handler stripped from the hook-detached descendant'
              );

              // App-side store-and-rerender must expose no executable sink.
              var probe = document.createElement('div');
              probe.innerHTML = ret.outerHTML + tail.outerHTML;
              assert.notOk(
                probe.querySelector('[onerror],[onload],script'),
                'no executable sink survives serialize/reparse: ' +
                  probe.innerHTML
              );
            }
          );

          QUnit.test(
            'IN_PLACE: ' +
              hook +
              ' detached deep subtree keeps only allowed attributes (' +
              site.id +
              ')',
            function (assert) {
              var root = document.createElement('div');
              root.innerHTML =
                '<article onclick="alert(1)"><p><span><img id="deep" ' +
                'class="keep" title="t" onload="alert(2)" onerror="alert(3)">' +
                '</span></p><svg><a onfocus="alert(4)"></a></svg></article>' +
                '<p id="kept" onmouseover="alert(5)">safe</p>';
              var article = root.querySelector('article');
              var deep = root.querySelector('#deep');
              var svgLink = root.querySelector('svg a');

              purify.addHook(hook, function (node) {
                if (node.nodeName === 'ARTICLE') {
                  _detach(node);
                }
              });

              purify.sanitize(root, { IN_PLACE: true });

              assert.strictEqual(
                article.getAttribute('onclick'),
                null,
                'handler stripped from the detached node itself'
              );
              assert.strictEqual(
                deep.getAttribute('onload'),
                null,
                'onload stripped from a deeply nested detached descendant'
              );
              assert.strictEqual(
                deep.getAttribute('onerror'),
                null,
                'onerror stripped from a deeply nested detached descendant'
              );
              assert.strictEqual(
                svgLink.getAttribute('onfocus'),
                null,
                'handler stripped from a detached foreign-content descendant'
              );
              assert.equal(
                deep.getAttribute('class'),
                'keep',
                'allow-listed attributes on detached nodes are left alone'
              );
              assert.equal(
                deep.getAttribute('title'),
                't',
                'allow-listed attributes on detached nodes are left alone'
              );
              assert.strictEqual(
                root.querySelector('#kept').getAttribute('onmouseover'),
                null,
                'the remaining in-place tree is still sanitized'
              );
            }
          );
        });

        // The afterSanitizeElements site that runs on a custom element kept
        // via CUSTOM_ELEMENT_HANDLING (GHSA-c2j3-45gr-mqc4) is a separate hook
        // site from the normal-element tail and needs the same detach
        // re-check.
        QUnit.test(
          'IN_PLACE: afterSanitizeElements node.remove() on a kept custom element neutralizes the detached subtree (CVE-2026-109345)',
          function (assert) {
            var root = document.createElement('div');
            root.innerHTML =
              '<x-wrap><img id="tail" onerror="alert(1)"></x-wrap>' +
              '<div>safe</div>';
            var tail = root.querySelector('#tail');

            purify.addHook('afterSanitizeElements', function (node) {
              if (node.nodeName === 'X-WRAP') {
                _detach(node);
              }
            });

            var ret = purify.sanitize(root, {
              IN_PLACE: true,
              CUSTOM_ELEMENT_HANDLING: { tagNameCheck: /^x-/ },
            });

            assert.equal(ret, root, 'returns the same in-place node');
            assert.notOk(
              ret.querySelector('x-wrap, #tail'),
              'detached subtree is absent from the returned tree'
            );
            assert.strictEqual(
              tail.getAttribute('onerror'),
              null,
              'on* handler stripped from the hook-detached descendant'
            );
          }
        );

        QUnit.test(
          'IN_PLACE: a hook-detached clobbered form subtree is neutralized (CVE-2026-75838)',
          function (assert) {
            var root = document.createElement('div');
            root.innerHTML =
              '<form onreset="alert(2)"><input name="removeAttribute">' +
              '<input name="removeAttributeNode"><input name="attributes">' +
              '<img id="clobbered-tail" onerror="alert(1)"></form>';
            var form = root.querySelector('form');
            var tail = root.querySelector('#clobbered-tail');

            purify.addHook('beforeSanitizeElements', function (node) {
              if (node.nodeName === 'FORM') {
                _detach(node);
              }
            });

            purify.sanitize(root, { IN_PLACE: true });

            assert.equal(root.innerHTML, '', 'the form is gone from the tree');
            assert.strictEqual(
              form.getAttribute('onreset'),
              null,
              'handler stripped from the detached clobbered form itself'
            );
            assert.strictEqual(
              tail.getAttribute('onerror'),
              null,
              'handler stripped below a detached clobbered form'
            );
          }
        );

        QUnit.test(
          'IN_PLACE: a parent-less root is not mistaken for a hook-detached node (CVE-2026-75838)',
          function (assert) {
            var root = document.createElement('div');
            root.setAttribute('class', 'root');
            root.setAttribute('onclick', 'alert(1)');
            root.innerHTML = '<b class="x" onclick="alert(2)">ok</b>';

            var seen = [];
            purify.addHook('uponSanitizeElement', function (node, data) {
              seen.push(data.tagName);
            });

            var ret = purify.sanitize(root, { IN_PLACE: true });

            assert.equal(ret, root, 'returns the same in-place node');
            assert.equal(
              root.outerHTML,
              '<div class="root"><b class="x">ok</b></div>',
              'root and children are sanitized as before'
            );
            assert.deepEqual(
              seen,
              ['div', 'b', '#text'],
              'the walk still visits every node of a parent-less root'
            );
          }
        );

        QUnit.test(
          'Non-IN_PLACE: a hook-detached subtree is dropped from the output (CVE-2026-75838)',
          function (assert) {
            purify.addHook('uponSanitizeElement', function (node) {
              if (node.nodeName === 'SECTION') {
                _detach(node);
              }
            });

            assert.equal(
              purify.sanitize(
                '<section><img src=x onerror=alert(1)></section><b>ok</b>'
              ),
              '<b>ok</b>',
              'string path output is unchanged'
            );
          }
        );

        QUnit.test(
          'IN_PLACE: a clobbered ownerDocument does not skip the sanitize walk (CVE-2026-75838)',
          function (assert) {
            // HTMLFormElement has [LegacyOverrideBuiltIns], so a child
            // <input name="ownerDocument"> (or a form-associated external
            // input) shadows Node.prototype.ownerDocument and a direct
            // form.ownerDocument read returns that <input>. The iterator was
            // built with createNodeIterator.call(root.ownerDocument, ...),
            // which then threw "Illegal invocation" before the walk, leaving
            // an armed descendant in the caller's live tree. jsdom does not
            // implement the form named-getter override, so reproduce it
            // faithfully: an own accessor shadowing the prototype getter is
            // exactly what [LegacyOverrideBuiltIns] surfaces.
            var root = document.createElement('form');
            var img = document.createElement('img');
            img.setAttribute('onerror', 'alert(1)'); // no src: assert the attr
            root.appendChild(img);
            document.body.appendChild(root);

            var fake = document.createElement('input');
            Object.defineProperty(root, 'ownerDocument', {
              get: function () {
                return fake;
              },
              configurable: true,
            });

            try {
              assert.strictEqual(
                root.ownerDocument,
                fake,
                'precondition: ownerDocument read is clobbered'
              );

              // The security invariant holds whether the call returns or
              // throws: the armed handler must be gone either way.
              try {
                purify.sanitize(root, { IN_PLACE: true });
              } catch (_) {}

              assert.strictEqual(
                img.getAttribute('onerror'),
                null,
                'armed on* handler stripped despite the ownerDocument clobber'
              );
            } finally {
              delete root.ownerDocument;
              root.parentNode.removeChild(root);
            }
          }
        );

        QUnit.test(
          'IN_PLACE: form with a natural ownerDocument-clobbering child stays safe (CVE-2026-75838)',
          function (assert) {
            // The real-vector form of the test above. In a clobbering-capable
            // engine the named child makes root.ownerDocument return the
            // input; in jsdom it does not. Either way, no on* handler may
            // survive.
            var root = document.createElement('form');
            root.innerHTML =
              '<input name="ownerDocument"><img onerror="alert(1)">';
            document.body.appendChild(root);

            var clobbers = root.ownerDocument !== document;
            try {
              try {
                purify.sanitize(root, { IN_PLACE: true });
              } catch (_) {}

              assert.notOk(
                /onerror/i.test(root.outerHTML),
                (clobbers
                  ? 'clobbering engine: on-handler stripped: '
                  : 'non-clobbering engine: on-handler stripped: ') +
                  root.outerHTML
              );
            } finally {
              root.parentNode.removeChild(root);
            }
          }
        );
      }
    );
  };
});
