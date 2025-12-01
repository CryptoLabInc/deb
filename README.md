
## C++ template repository

- You can start your c++ repository starting from this template repository and customize if needed.
- You may install [pre-commit](https://pre-commit.com/) through `pip install pre-commit` and do `pre-commit install`.
  - Customize the pre-commit configuration in `.pre-commit-config.yaml`.
- Any changes are welcome!

### Build
```sh
cmake --preset release && cmake --build --preset ci && ctest --preset all-test
```

### Best practices
- Follow [CppCoreGuidelines](https://github.com/isocpp/CppCoreGuidelines).
- For cmake, follow [Modern cmake](https://cliutils.gitlab.io/modern-cmake/chapters/install/installing.html) and [More modern cmake](https://hsf-training.github.io/hsf-training-cmake-webpage/aio/index.html) as much as you can.
- See also other cpp templates like [modern-cpp-template](https://github.com/filipdutescu/modern-cpp-template), [gui_starter_template](https://github.com/cpp-best-practices/gui_starter_template), or [ModernCppStarter](https://github.com/TheLartians/ModernCppStarter) to learn more.

### Misc
- If `clang-tidy` outputs errors on 3rd party headers, change `HeaderFilterRegex` in `.clang-tidy`.

### TODOs
- Add code coverage support for both lcov and gcov.
- Add valgrind support.
- Lint clang-tidy-diff support.
- Make `main.yml` check the all hooks via `pre-commit run --hook-stage push`

### License
deb is licensed under the Apache License 2.0, which means that you are free to get and use it for commercial and non-commercial purposes as long as you fulfill its conditions.

See the LICENSE file for more details.

### Contact

juny2400@cryptolab.co.kr
leejonghyeong@cryptolab.co.kr
