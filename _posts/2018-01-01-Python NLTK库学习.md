---
layout: post
title: "Python NLTK库学习"
date: 2018-01-01
description: "Python SciPy库学习笔记"
tag: 机器学习
---
## 前言
元旦跨年码代码T-T 

### NLTK
NLTK在NLP领域中是最常使用的一个Python库，包括图形演示和示例数据，其提供的教程解释了工具包支持的语言处理任务背后的基本概念。

#### 安装方法
```
pip install -U nltk
```

#### 加载数据
```
>>> import nltk
>>> nltk.download()
showing info https://raw.githubusercontent.com/nltk/nltk_data/gh-pages/index.xml
```
#### 用法示例
分词与标识：
```
>>> import nltk
s>>> sentence = """At eight o'clock on Thursday morning
... Arthur didn't feel very good."""
>>> tokens = nltk.word_tokenize(sentence)
>>> tokens
['At', 'eight', "o'clock", 'on', 'Thursday', 'morning', 'Arthur', 'did', "n't", 'feel', 'very', 'good', '.']
>>> tagged = nltk.pos_tag(tokens)
>>> tagged[0:6]
[('At', 'IN'), ('eight', 'CD'), ("o'clock", 'NN'), ('on', 'IN'), ('Thursday', 'NNP'), ('morning', 'NN')]
```

标识名词实体：
```
>>> entities = nltk.chunk.ne_chunk(tagged)
>>> entities
Tree('S', [('At', 'IN'), ('eight', 'CD'), ("o'clock", 'NN'), ('on', 'IN'), ('Thursday', 'NNP'), ('morning', 'NN'), Tree('PERSON', [('Arthur', 'NNP')]), ('did', 'VBD'), ("n't", 'RB'), ('feel', 'VB'), ('very', 'RB'), ('good', 'JJ'), ('.', '.')])
```

展现语法树
```
>>> from nltk.corpus import treebank
>>> t = treebank.parsed_sents('wsj_0001.mrg')[0]
>>> t.draw()
```
![](/images/2018-01-01/1.png)

