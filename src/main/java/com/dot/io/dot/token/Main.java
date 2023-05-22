package com.dot.io.dot.token;

import io.token.proto.PagedList;
import io.token.proto.common.account.AccountProtos;
import io.token.proto.common.alias.AliasProtos;
import io.token.proto.common.security.SecurityProtos;
import io.token.proto.common.transaction.TransactionProtos;
import io.token.security.UnsecuredFileSystemKeyStore;
import io.token.tokenrequest.TokenRequest;
import io.token.tokenrequest.TokenRequestResult;
import io.token.tpp.Account;
import io.token.tpp.Member;
import io.token.tpp.Representable;
import io.token.tpp.TokenClient;
import lombok.extern.slf4j.Slf4j;
import spark.Spark;

import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

import static io.token.TokenClient.TokenCluster.SANDBOX;
import static io.token.proto.common.alias.AliasProtos.Alias.Type.DOMAIN;
import static io.token.proto.common.token.TokenProtos.TokenRequestPayload.AccessBody.ResourceType.*;
import static io.token.util.Util.generateNonce;

@Slf4j
public class Main {

    private static final int PORT = 3000;
    private static final String REDIRECT_URL = "http://localhost:" + PORT + "/callback";

    public static void main(String[] args) throws Exception {
        new Main().start();
    }

    public void start() throws Exception {
        TokenClient client = prepareClient();
        Member member = getMember(client);

        setupCallback(client, member);

        redirectToUrl(genereateRedirectUrl(client, member));
    }

    private void setupCallback(TokenClient client, Member member) {
        Spark.port(PORT);

        Spark.get("/callback", (req, res) -> {
            res.status(200);
            return fetchData(client, member, req.queryParams("request-id"));
        });
    }

    private String fetchData(TokenClient client, Member member, String requestId) {
        TokenRequestResult requestResult = client.getTokenRequestResultBlocking(requestId);
        String tokenId = requestResult.getTokenId();

        Representable representable = member.forAccessToken(tokenId);

        StringBuilder outputBuilder = new StringBuilder();
        outputBuilder.append("<h1>Aggregation results</h1>");

        fetchAccounts(representable, outputBuilder);

        return outputBuilder.toString();
    }

    private void fetchAccounts(Representable representable, StringBuilder outputBuilder) {
        List<Account> accounts = representable.getAccountsBlocking();

        for (Account account : accounts) {
            AccountProtos.AccountDetails accountDetails = account.accountDetails();
            TransactionProtos.Balance balance = account.getBalanceBlocking(SecurityProtos.Key.Level.PRIVILEGED);


            outputBuilder.append("<h2>Account</h2>");

            outputBuilder.append("<table>");
            outputBuilder.append("<thead><tr>");
            outputBuilder.append("<th>Holder name</th>");
            outputBuilder.append("<th>Account identifiers</th>");
            outputBuilder.append("<th>Account type</th>");
            outputBuilder.append("<th>Available balance</th>");
            outputBuilder.append("<th>Current balance</th>");
            outputBuilder.append("<th>Currency</th>");
            outputBuilder.append("</tr></thead>");

            outputBuilder.append("<tbody>");
            outputBuilder.append("<tr>");

            outputBuilder.append("<td>" + accountDetails.getAccountHolderName() + "</td>");

            outputBuilder.append("<td><ul>");
            for (AccountProtos.AccountIdentifier identifier : accountDetails.getAccountIdentifiersList()) {
                outputBuilder.append("<li>" + identifier.toString() + "</li>");
            }
            outputBuilder.append("</ul></td>");

            outputBuilder.append("<td>" + accountDetails.getType().name() + "</td>");
            outputBuilder.append("<td>" + balance.getAvailable().getValue() + "</td>");
            outputBuilder.append("<td>" + balance.getCurrent().getValue() + "</td>");
            outputBuilder.append("<td>" + balance.getAvailable().getCurrency() + "</td>");

            outputBuilder.append("</tr>");
            outputBuilder.append("</tbody></table>");

            fetchTransactions(account, outputBuilder);
        }

    }

    private void fetchTransactions(Account account, StringBuilder outputBuilder) {
        PagedList<TransactionProtos.Transaction, String> transactionPagedList = account.getTransactionsBlocking(null, 100, SecurityProtos.Key.Level.PRIVILEGED);

        outputBuilder.append("<h2>Transactions</h2>");

        outputBuilder.append("<table>");
        outputBuilder.append("<thead><tr>");
        outputBuilder.append("<th>ID</th>");
        outputBuilder.append("<th>Status</th>");
        outputBuilder.append("<th>Amount</th>");
        outputBuilder.append("<th>Currency</th>");
        outputBuilder.append("<th>Created at</th>");
        outputBuilder.append("<th>Creditor (account identifiers)</th>");
        outputBuilder.append("<th>Creditor (customer data)</th>");
        outputBuilder.append("</tr></thead>");

        outputBuilder.append("<tbody>");

        for (TransactionProtos.Transaction transaction : transactionPagedList.getList()) {
            outputBuilder.append("<tr>");

            outputBuilder.append("<td>" + transaction.getId() + "</td>");
            outputBuilder.append("<td>" + transaction.getStatus().name() + "</td>");
            outputBuilder.append("<td>" + transaction.getAmount().getValue() + "</td>");
            outputBuilder.append("<td>" + transaction.getAmount().getCurrency() + "</td>");
            outputBuilder.append("<td>" + transaction.getCreatedAtMs() + "</td>");
            outputBuilder.append("<td>" + transaction.getCreditorEndpoint().getAccountIdentifier() + "</td>");
            outputBuilder.append("<td>" + transaction.getCreditorEndpoint().getCustomerData() + "</td>");

            outputBuilder.append("</tr>");
        }
        outputBuilder.append("</tbody></table>");
    }

    private TokenClient prepareClient() throws IOException {
        Path keysPath = Files.createDirectories(Paths.get("./keys"));

        return TokenClient.builder()
                .connectTo(SANDBOX)
                .withKeyStore(new UnsecuredFileSystemKeyStore(keysPath.toFile()))
                .build();
    }

    private Member getMember(TokenClient client) {
        File keysDir = new File("./keys");
        String[] paths = keysDir.list();

        return Arrays.stream(paths)
                .filter(path -> path.contains("_"))
                .map(path -> path.replace("_", ":"))
                .findFirst()
                .map(client::getMemberBlocking)
                .orElseGet(() -> createMember(client));
    }

    private Member createMember(TokenClient client) {
        String email = generateNonce().toLowerCase() + "-test+noverify@example.com";

        AliasProtos.Alias alias = AliasProtos.Alias.newBuilder()
                .setType(DOMAIN)
                .setValue(email)
                .build();

        Member member = client.createMemberBlocking(alias);
        member.addRedirectUrlsBlocking(List.of(REDIRECT_URL));

        return member;
    }

    private String genereateRedirectUrl(TokenClient client, Member member) {
        String refId = generateNonce();

        TokenRequest request = TokenRequest.accessTokenRequestBuilder(ACCOUNTS, BALANCES, TRANSACTIONS)
                .setRefId(refId)
                .setToMemberId(member.memberId())
                .setRedirectUrl(REDIRECT_URL)
                .setToAlias(member.firstAliasBlocking())
                .build();

        String requestId = member.storeTokenRequestBlocking(request);

        return client.generateTokenRequestUrlBlocking(requestId);
    }

    private void redirectToUrl(String url) throws Exception {
        if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            Desktop.getDesktop().browse(new URI(url));
        } else {
            System.out.println("REDIRECT!");
            System.out.println("Open this link: " + url);
        }
    }
}
