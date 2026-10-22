# Preparar publicação no GitHub

## Conteúdo

Publique o pacote `port_scanner/`, os testes, a documentação, o lançador `scanner.py`, `pyproject.toml`, `MANIFEST.in`, `.gitignore` e `.github/workflows/tests.yml`.

`local/` contém arquivos anteriores sem relação com o scanner, inclusive dados pessoais. Foi preservado apenas localmente e deve permanecer fora do repositório e dos pacotes. `.gitignore` também exclui ambientes virtuais, credenciais locais, caches e resultados de varredura. Exclusões não removem arquivos já presentes em um histórico Git; revise o histórico antes de publicar um repositório existente.

## Verificação

```bash
python3 -m unittest discover -s tests -v
RUN_NETWORK_TESTS=1 python3 -m unittest discover -s tests -v
python3 -m pip install .
port-scanner --help
```

Em PowerShell, defina `$env:RUN_NETWORK_TESTS = "1"` antes do comando de testes. O workflow executa instalação e testes em Linux, Windows e macOS.

Antes do primeiro envio, escolha a licença do projeto e adicione seu texto. A autoria e a concessão de uma licença devem ser definidas pelo proprietário.
