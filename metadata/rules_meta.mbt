///|
/// M 规则（元数据）：moon.mod 层面的 typosquat / 官方仿冒 / 空壳 / 仓库不一致 / 依赖混淆

///|
/// 官方 moonbitlang 仓库名集合，不得被第三方仿冒
pub fn official_repo_names() -> Array[String] {
  ["core", "async", "x", "parser", "yacc", "quickcheck"]
}

///|
/// "author/repo" 的 repo 段；无斜杠时整个字符串即 repo
fn repo_of(name : String) -> String {
  match name.find("/") {
    Some(i) => name[i + 1:].to_owned()
    None => name
  }
}

///|
/// "author/repo" 的 author 段；无斜杠时为空
fn author_of(name : String) -> String {
  match name.find("/") {
    Some(i) => name[:i].to_owned()
    None => ""
  }
}

///|
/// URL 路径段（去掉 scheme 后按 "/" 切分）
fn url_segments(url : String) -> Array[String] {
  let t = url.trim(chars="/").to_owned()
  match t.find("://") {
    Some(p) => {
      let rest = t[p + 3:].to_owned()
      let segs : Array[String] = []
      for seg in rest.split("/") {
        segs.push(seg.to_owned())
      }
      segs
    }
    None => []
  }
}

///|
/// URL 的 repo 段（倒数第一段）；pub 供后续规则复用
pub fn repo_of_url(url : String) -> String {
  let segs = url_segments(url)
  if segs.length() >= 2 {
    segs[segs.length() - 1]
  } else {
    ""
  }
}

///|
/// URL 的 owner 段（倒数第二段）
fn owner_of_url(url : String) -> String {
  let segs = url_segments(url)
  if segs.length() >= 2 {
    segs[segs.length() - 2]
  } else {
    ""
  }
}

///|
/// M01：repo 名与 hotlist 中 repo 名 DL ≤2 且不同名且**非同一作者** → High
/// （每个模块至多一条，首个命中即止）。同一作者不会 typosquat 自己的热门包
/// （真实案例：vectie/moonclaw vs hotlist 中的 vectie/moonflow，DL=2 但同为 vectie）。
/// 提供注册表权威名时以权威名的 repo 段参与比对（防 manifest 声明名伪装绕过）。
/// 短名分级阈值：repo 名 <8 字符时要求 DL ≤1（短名 DL≤2 碰撞过于随机）。
pub fn m01(
  m : Manifest,
  hotlist : Array[String],
  authoritative? : String = "",
) -> Array[@engine.Finding] {
  let rd : @engine.RuleDef = {
    id: "M01",
    severity: @engine.High,
    category: @engine.Metadata,
    description: "typosquatting",
  }
  let cmp = if authoritative != "" { authoritative } else { m.name }
  let repo = repo_of(cmp)
  let author = author_of(cmp)
  let threshold = if repo.length() < 8 { 1 } else { 2 }
  let fs : Array[@engine.Finding] = []
  for hot in hotlist {
    let hrepo = repo_of(hot)
    if hrepo == repo {
      continue
    }
    // 同一作者豁免：hot 条目带 author 且与被测模块一致 → 跳过
    let hauthor = author_of(hot)
    if hauthor != "" && author != "" && hauthor == author {
      continue
    }
    // 短 repo 名（<5 字符）的 DL 碰撞过于随机（elk/pkl、json/jsoo）→ 不比对
    if repo.length() >= 5 && hrepo.length() >= 5 {
      if @matchers.damerau_levenshtein(repo, hrepo) <= threshold {
        fs.push(
          rd.finding(
            file="moon.mod",
            line=1,
            snippet=cmp,
            message="name similar to popular module \{hot}",
          ),
        )
        break
      }
    }
  }
  fs
}

///|
/// M02：author ≠ moonbitlang 但 repo ∈ 官方名集 → Critical（官方仓仿冒）；
/// 或 author 与官方 org 名过近（DL ≤2 且 ≥8 字符）→ Critical（官方作者仿冒，
/// 如 moonbitlang-team / moonbitlangs / moonbltlang）。
/// 提供权威名时 author 取权威名（注册者），而官方名比对同时覆盖声明名与权威名
/// （evil/asynx 声明 name = "moonbitlang/async" 时 repo "async" 命中官方集）。
/// 官方 repo 比较大小写不敏感（Core/core 视为同名仿冒）。
pub fn m02(
  m : Manifest,
  authoritative? : String = "",
) -> Array[@engine.Finding] {
  let author = if authoritative != "" {
    author_of(authoritative)
  } else {
    author_of(m.name)
  }
  if author == "moonbitlang" {
    return []
  }
  let official_hit = (n : String) => {
    let repo = repo_of(n).to_lower()
    official_repo_names().iter().any(o => o.to_lower() == repo)
  }
  if official_hit(m.name) ||
    (authoritative != "" && official_hit(authoritative)) {
    let rd : @engine.RuleDef = {
      id: "M02",
      severity: @engine.Critical,
      category: @engine.Metadata,
      description: "official impersonation",
    }
    return [
      rd.finding(
        file="moon.mod",
        line=1,
        snippet=m.name,
        message="impersonates official moonbitlang module",
      ),
    ]
  }
  // 作者名仿冒：与 "moonbitlang" DL≤2（≥8 字符门槛排除随机短名碰撞）
  if author.length() >= 8 &&
    @matchers.damerau_levenshtein(author.to_lower(), "moonbitlang") <= 2 {
    let rd : @engine.RuleDef = {
      id: "M02",
      severity: @engine.Critical,
      category: @engine.Metadata,
      description: "official author lookalike",
    }
    return [
      rd.finding(
        file="moon.mod",
        line=1,
        snippet=author,
        message="author name close to official org \"moonbitlang\"",
      ),
    ]
  }
  []
}

///|
/// M03：readme 过短且无测试且 name 非空 → Medium（空壳模块）
pub fn m03(
  m : Manifest,
  readme_len : Int,
  has_tests : Bool,
) -> Array[@engine.Finding] {
  if readme_len < 200 && !has_tests && m.name.length() > 0 {
    let rd : @engine.RuleDef = {
      id: "M03",
      severity: @engine.Medium,
      category: @engine.Metadata,
      description: "empty shell",
    }
    [
      rd.finding(
        file="moon.mod",
        line=1,
        snippet=m.name,
        message="no substantial readme and no tests",
      ),
    ]
  } else {
    []
  }
}

///|
/// M04：repository 为空 → Low；URL owner 段与模块 author 不一致 → Medium。
/// 提供权威名时 author 取权威名的 author 段（防声明名伪装）。
pub fn m04(
  m : Manifest,
  authoritative? : String = "",
) -> Array[@engine.Finding] {
  if m.repository.length() == 0 {
    let rd : @engine.RuleDef = {
      id: "M04",
      severity: @engine.Low,
      category: @engine.Metadata,
      description: "missing repository",
    }
    return [
      rd.finding(
        file="moon.mod",
        line=1,
        snippet="",
        message="no repository field",
      ),
    ]
  }
  let owner = owner_of_url(m.repository)
  let author = if authoritative != "" {
    author_of(authoritative)
  } else {
    author_of(m.name)
  }
  // GitHub 登录名大小写不敏感（Across2005/across2005 为同一 owner）
  if owner.length() > 0 &&
    author.length() > 0 &&
    owner.to_lower() != author.to_lower() {
    let rd : @engine.RuleDef = {
      id: "M04",
      severity: @engine.Medium,
      category: @engine.Metadata,
      description: "repository owner mismatch",
    }
    [
      rd.finding(
        file="moon.mod",
        line=1,
        snippet=m.repository,
        message="repository owner \{owner} != module author \{author}",
      ),
    ]
  } else {
    []
  }
}

///|
/// M05：依赖 repo 名与 hotlist/官方名过近（排除同名与**自有依赖**）→ High（每依赖一条）。
/// 自有依赖豁免：依赖的 author 与模块 author 相同时不构成冒名（真实案例：
/// mizchi/actrun 依赖自己的 mizchi/moomaid，被 QuietlyChan/moonai 的 DL=2 撞名误报）。
/// 短名分级阈值：双方 repo 名均 <8 字符时要求 DL ≤1（moonlib/moonai 这类
/// 7 字符 DL=2 属随机碰撞），≥8 字符维持 DL ≤2。
pub fn m05(m : Manifest, hotlist : Array[String]) -> Array[@engine.Finding] {
  let rd : @engine.RuleDef = {
    id: "M05",
    severity: @engine.High,
    category: @engine.Metadata,
    description: "dependency confusion",
  }
  let author = author_of(m.name)
  let near = (drepo : String, target : String) => {
    drepo != target &&
    drepo.length() >= 5 &&
    target.length() >= 5 &&
    ({
      let cap = if drepo.length() < 8 || target.length() < 8 { 1 } else { 2 }
      @matchers.damerau_levenshtein(drepo, target) <= cap
    })
  }
  let fs : Array[@engine.Finding] = []
  for dep in m.deps {
    // 自有依赖豁免
    let dauthor = author_of(dep)
    if author != "" && dauthor != "" && dauthor == author {
      continue
    }
    let drepo = repo_of(dep)
    let near_hot = hotlist.iter().any(h => near(drepo, repo_of(h)))
    let near_official = official_repo_names().iter().any(o => near(drepo, o))
    if near_hot || near_official {
      fs.push(
        rd.finding(
          file="moon.mod",
          line=1,
          snippet=dep,
          message="dependency name close to known module",
        ),
      )
    }
  }
  fs
}
