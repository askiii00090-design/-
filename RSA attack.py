import math


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def ext_gcd(a, b):
    x0, x1 = 1, 0
    y0, y1 = 0, 1
    while b != 0:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def mod_inverse(e, phi):
    g, x, _ = ext_gcd(e, phi)
    if g != 1:
        return None
    return x % phi


def is_square(n):
    if n < 0:
        return False
    return math.isqrt(n) ** 2 == n


def integer_nth_root(n, e):
    if n < 0 or e <= 0:
        return None, False

    left = 0
    right = max(1, n)

    while left <= right:
        mid = (left + right) // 2
        power = mid ** e

        if power == n:
            return mid, True
        elif power < n:
            left = mid + 1
        else:
            right = mid - 1

    return right, False


def generate_keys(p, q, e=65537):
    N = p * q
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)

    if d is None:
        raise ValueError("Не удалось найти обратный элемент d")

    return (e, N), (d, N)


def encrypt(message, public_key):
    e, N = public_key
    return pow(message, e, N)


def decrypt(ciphertext, private_key):
    d, N = private_key
    return pow(ciphertext, d, N)


def fermat_factorization(N, max_steps=1000):
    if N <= 0:
        return None, None, 0

    x = math.isqrt(N)
    if x * x < N:
        x += 1

    steps = 0

    while steps < max_steps:
        y_sq = x * x - N

        if is_square(y_sq):
            y = math.isqrt(y_sq)
            p = x + y
            q = x - y
            if p > 1 and q > 1 and p * q == N:
                return p, q, steps + 1

        x += 1
        steps += 1

    return None, None, steps


def common_factor_attack_and_recover_d(N1, N2, e):
    p = gcd(N1, N2)

    if p == 1 or p == N1 or p == N2:
        return None, None, None, None

    q1 = N1 // p
    phi1 = (p - 1) * (q1 - 1)
    d1 = mod_inverse(e, phi1)

    if d1 is None:
        return None, None, None, None

    return p, q1, phi1, d1


def low_exponent_attack(C, e, N):
    if C < 0 or e <= 0:
        return None, False

    m, exact = integer_nth_root(C, e)

    if not exact:
        return None, False

    if pow(m, e, N) == C:
        return m, True

    return None, False


def safe_rsa_demo():
    p = 1300003
    q = 1700033
    return generate_keys(p, q, 65537)


def weak_rsa_for_fermat():
    p = 10000000000000000000000000000000000000397
    q = 10000000000000000000000000000000000000563
    return generate_keys(p, q, 65537)


def rsa_pair_with_common_factor():
    p = 1000003
    q1 = 1000033
    q2 = 1000037

    public_key_1, private_key_1 = generate_keys(p, q1, 65537)
    public_key_2, private_key_2 = generate_keys(p, q2, 65537)

    return public_key_1, private_key_1, public_key_2, private_key_2


def low_e_demo():
    e = 3
    p = 1000003
    q = 1000033
    public_key, private_key = generate_keys(p, q, e)

    message = 123
    ciphertext = pow(message, e)

    return public_key, private_key, message, ciphertext


def show_menu():
    print("====== RSA LAB ======")
    print("1. Сгенерировать безопасный RSA")
    print("2. Сгенерировать слабый RSA для Ферма")
    print("3. Сгенерировать две пары с общим множителем")
    print("4. Запустить атаку Ферма")
    print("5. Запустить атаку общего множителя")
    print("6. Запустить атаку при малом e")
    print("7. Шифрование и расшифрование")
    print("0. Выход")


def main():
    public_key = None
    private_key = None

    public_key_1 = None
    private_key_1 = None
    public_key_2 = None
    private_key_2 = None

    while True:
        show_menu()
        choice = input("Выбор: ").strip()

        if choice == "1":
            try:
                public_key, private_key = safe_rsa_demo()
                print("Безопасный RSA создан.")
                print("Public key:", public_key)
                print("Private key:", private_key)
            except Exception:
                print("Не удалось создать RSA.")

        elif choice == "2":
            try:
                public_key, private_key = weak_rsa_for_fermat()
                print("Слабый RSA для Ферма создан.")
                print("Public key:", public_key)
                print("Private key:", private_key)
            except Exception:
                print("Не удалось создать слабый RSA.")

        elif choice == "3":
            try:
                public_key_1, private_key_1, public_key_2, private_key_2 = rsa_pair_with_common_factor()
                print("Две пары с общим множителем созданы.")
                print("N1:", public_key_1[1])
                print("N2:", public_key_2[1])
            except Exception:
                print("Не удалось создать пары.")

        elif choice == "4":
            if public_key is None:
                print("Сначала сгенерируй слабый RSA.")
                continue

            N = public_key[1]
            print("Запуск Ферма...")
            p, q, steps = fermat_factorization(N)

            if p is None:
                print("Атака не сработала.")
                continue

            print("Успех.")
            print("p =", p)
            print("q =", q)
            print("steps =", steps)

        elif choice == "5":
            if public_key_1 is None or public_key_2 is None:
                print("Сначала создай пару с общим множителем.")
                continue

            N1 = public_key_1[1]
            N2 = public_key_2[1]
            e = public_key_1[0]

            print("Запуск атаки общего множителя...")
            p, q1, phi1, d1 = common_factor_attack_and_recover_d(N1, N2, e)

            if p is None:
                print("Атака не сработала.")
                continue

            print("Успех.")
            print("Общий множитель p =", p)
            print("q1 =", q1)
            print("phi(N1) =", phi1)
            print("d1 =", d1)

        elif choice == "6":
            try:
                public_key_low, private_key_low, message, ciphertext = low_e_demo()
                e, N = public_key_low

                print("Демонстрация атаки при малом e")
                print("e =", e)
                print("N =", N)
                print("message =", message)
                print("ciphertext =", ciphertext)

                recovered, success = low_exponent_attack(ciphertext, e, N)

                if success:
                    print("Атака успешна.")
                    print("Восстановленное сообщение =", recovered)
                else:
                    print("Атака не сработала.")
            except Exception:
                print("Атака не сработала.")

        elif choice == "7":
            if public_key is None or private_key is None:
                print("Сначала сгенерируй RSA.")
                continue

            try:
                message = int(input("Введите число: "))
                C = encrypt(message, public_key)
                M = decrypt(C, private_key)

                print("Шифротекст:", C)
                print("Расшифровка:", M)
            except ValueError:
                print("Нужно ввести целое число.")
            except Exception:
                print("Ошибка шифрования/расшифрования.")

        elif choice == "0":
            print("Выход.")
            break

        else:
            print("Неверный выбор.")


if __name__ == "__main__":
    main()
