<?php
include 'conexao.php'; 

header('Content-Type: application/json');

// Verifica se o método de requisição é POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405); // Método Não Permitido
    echo json_encode(['sucesso' => false, 'mensagem' => 'Método não permitido.']);
    exit;
}

// 2. Coletar e Sanitizar Dados (Usando os nomes dos campos do registrese.html)
// É fundamental usar prepared statements para prevenir SQL Injection.
$nome_completo = trim($_POST['nome'] ?? '');
$data_nascimento = $_POST['datanasc'] ?? '';
$cpf = trim($_POST['cpf'] ?? '');
$telefone = trim($_POST['telefone'] ?? '');
$email = trim(strtolower($_POST['email'] ?? '')); // Armazena e-mail em minúsculas
$username = trim(strtolower($_POST['usuario'] ?? '')); // Armazena usuário em minúsculas
$senha_pura = $_POST['senha'] ?? '';
$confirmasenha = $_POST['confirmasenha'] ?? '';


// Validação de Senhas no Back-end (redundante, mas seguro)
if ($senha_pura !== $confirmasenha) {
    echo json_encode(['sucesso' => false, 'mensagem' => 'As senhas não coincidem.']);
    exit;
}

// Validação de Campos Obrigatórios (Conforme o enunciado)
if (empty($username) || empty($email) || empty($senha_pura) || empty($nome_completo)) {
    echo json_encode(['sucesso' => false, 'mensagem' => 'Preencha todos os campos obrigatórios.']);
    exit;
}

// Validação de formato de E-mail
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(['sucesso' => false, 'mensagem' => 'Formato de email inválido.']);
    exit;
}

// 3. Checar duplicidade (username/email)
try {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM usuarios WHERE username = :username OR email = :email");
    $stmt->execute(['username' => $username, 'email' => $email]);
    $count = $stmt->fetchColumn();

    if ($count > 0) {
        echo json_encode(['sucesso' => false, 'mensagem' => 'Usuário ou Email já cadastrados.']);
        exit;
    }
} catch (PDOException $e) {
    // Erro de DB ao checar duplicidade
    error_log("Erro ao checar duplicidade: " . $e->getMessage());
    echo json_encode(['sucesso' => false, 'mensagem' => 'Erro interno do servidor.']);
    exit;
}

// --- FIM DAS VALIDAÇÕES ---

// 4. Gerar hash da senha
$senha_hash = password_hash($senha_pura, PASSWORD_DEFAULT);


// 5. Inserir no DB (Se todas as validações passarem)
try {
    $sql = "INSERT INTO usuarios (nome_completo, data_nascimento, cpf, telefone, email, username, senha) 
            VALUES (:nome, :datanasc, :cpf, :telefone, :email, :usuario, :senha)";
    
    $stmt = $pdo->prepare($sql);
    
    $result = $stmt->execute([
        'nome' => $nome_completo,
        'datanasc' => $data_nascimento,
        'cpf' => $cpf,
        'telefone' => $telefone,
        'email' => $email,
        'usuario' => $username,
        'senha' => $senha_hash
    ]);

    if ($result) {
        // 6. Retornar JSON (sucesso: true)
        echo json_encode(['sucesso' => true, 'mensagem' => 'Cadastro realizado com sucesso!']);
    } else {
        // Retornar erro de inserção (6)
        echo json_encode(['sucesso' => false, 'mensagem' => 'Erro ao salvar o usuário.']);
    }

} catch (PDOException $e) {
    // Erro fatal de DB na inserção
    error_log("Erro fatal de DB no cadastro: " . $e->getMessage());
    echo json_encode(['sucesso' => false, 'mensagem' => 'Erro de comunicação com o banco de dados.']);
}
?>
